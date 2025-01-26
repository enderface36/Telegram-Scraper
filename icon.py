from PIL import Image
import os

def create_ico():
    # Open the source image
    img = Image.open('icon.jpg')
    
    # Convert to RGBA if needed
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Prepare different sizes needed for Windows
    sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
    icons = []
    
    # Create each size
    for size in sizes:
        resized_img = img.resize(size, Image.Resampling.LANCZOS)
        icons.append(resized_img)
    
    # Save as ICO with all sizes included
    icons[0].save('app.ico', format='ICO', sizes=sizes, append_images=icons[1:])

if __name__ == '__main__':
    create_ico() 