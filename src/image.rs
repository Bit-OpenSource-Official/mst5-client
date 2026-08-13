use image::imageops::FilterType;
use image::{DynamicImage, GenericImageView, ImageFormat};
use std::io::{self, Cursor, Read};

pub const MAX_IMAGE_INPUT_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_IMAGE_SOURCE_PIXELS: u64 = 64 * 1024 * 1024;
pub const MAX_IMAGE_OUTPUT_PIXELS: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    /// Android ARGB_8888 pixels represented as 0xAARRGGBB native u32 values.
    pub argb: Vec<u32>,
}

pub fn decode_image<R: Read>(
    mut reader: R,
    max_side: u32,
    max_pixels: u64,
) -> io::Result<DecodedImage> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_IMAGE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_IMAGE_INPUT_BYTES {
        return Err(invalid_input("image exceeds the 12 MiB decode limit"));
    }
    decode_image_bytes(&bytes, max_side, max_pixels)
}

pub fn decode_image_bytes(
    bytes: &[u8],
    max_side: u32,
    max_pixels: u64,
) -> io::Result<DecodedImage> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_INPUT_BYTES {
        return Err(invalid_input("image input must contain 1..12582912 bytes"));
    }
    let format = image::guess_format(bytes).map_err(image_error)?;
    if !matches!(
        format,
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP
    ) {
        return Err(invalid_input(
            "only JPEG, PNG and WebP images are supported",
        ));
    }
    let image = image::load_from_memory_with_format(bytes, format).map_err(image_error)?;
    let image = if format == ImageFormat::Jpeg {
        apply_exif_orientation(image, jpeg_orientation(bytes))
    } else {
        image
    };
    let (width, height) = image.dimensions();
    let source_pixels = u64::from(width).saturating_mul(u64::from(height));
    if width == 0 || height == 0 || source_pixels > MAX_IMAGE_SOURCE_PIXELS {
        return Err(invalid_input(
            "image dimensions exceed the 64 MP decode limit",
        ));
    }
    let max_side = max_side.max(1);
    let max_pixels = max_pixels.clamp(1, MAX_IMAGE_OUTPUT_PIXELS);
    let side_scale = (max_side as f64 / width.max(height) as f64).min(1.0);
    let pixel_scale = ((max_pixels as f64 / source_pixels as f64).sqrt()).min(1.0);
    let scale = side_scale.min(pixel_scale);
    let target_width = ((width as f64 * scale).round() as u32).max(1);
    let target_height = ((height as f64 * scale).round() as u32).max(1);
    let rgba = if target_width != width || target_height != height {
        image
            .resize_exact(target_width, target_height, FilterType::Triangle)
            .to_rgba8()
    } else {
        image.to_rgba8()
    };
    let argb = rgba
        .pixels()
        .map(|pixel| {
            let [red, green, blue, alpha] = pixel.0;
            (u32::from(alpha) << 24)
                | (u32::from(red) << 16)
                | (u32::from(green) << 8)
                | u32::from(blue)
        })
        .collect();
    Ok(DecodedImage {
        width: target_width,
        height: target_height,
        argb,
    })
}

fn jpeg_orientation(bytes: &[u8]) -> u32 {
    exif::Reader::new()
        .read_from_container(&mut Cursor::new(bytes))
        .ok()
        .and_then(|exif| {
            exif.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
                .and_then(|field| field.value.get_uint(0))
        })
        .unwrap_or(1)
}

fn apply_exif_orientation(image: DynamicImage, orientation: u32) -> DynamicImage {
    match orientation {
        2 => image.fliph(),
        3 => image.rotate180(),
        4 => image.flipv(),
        5 => image.rotate90().fliph(),
        6 => image.rotate90(),
        7 => image.rotate270().fliph(),
        8 => image.rotate270(),
        _ => image,
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn image_error(error: image::ImageError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    #[test]
    fn decodes_png_to_argb_and_resizes() {
        let image = ImageBuffer::from_pixel(8, 4, Rgba([0x12, 0x34, 0x56, 0x78]));
        let mut encoded = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(image)
            .write_to(&mut encoded, ImageFormat::Png)
            .unwrap();
        let decoded = decode_image_bytes(encoded.get_ref(), 4, 16).unwrap();
        assert_eq!((decoded.width, decoded.height), (4, 2));
        assert_eq!(decoded.argb, vec![0x7812_3456; 8]);
    }

    #[test]
    fn rejects_unsupported_input() {
        assert!(decode_image_bytes(b"not an image", 128, 1024).is_err());
    }
}
