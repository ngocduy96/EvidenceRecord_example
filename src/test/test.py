from PIL import Image

# Define image size and colors
width, height = 100, 100
white, black = 255, 0

# Create a new image with mode '1' (1-bit pixels, black and white)
image = Image.new('1', (width, height), white)

# Draw a pattern (e.g., a diagonal line)
for x in range(width):
    for y in range(height):
        if x == y:  # Diagonal line
            image.putpixel((x, y), black)

# Save the image in BMP format
image.save("output.bmp")

print("1-bit BMP image created and saved as 'output.bmp'.")