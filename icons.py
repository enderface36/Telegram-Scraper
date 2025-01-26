from PIL import Image, ImageDraw

def create_eye_icons():
    # Create eye-open icon
    img_open = Image.new('RGBA', (16, 16), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img_open)
    
    # Draw eye shape
    draw.ellipse([2, 4, 14, 12], outline=(100, 100, 100, 255), width=1)
    draw.ellipse([6, 6, 10, 10], fill=(100, 100, 100, 255))
    
    # Save eye-open icon
    img_open.save('eye-open.png', 'PNG')
    
    # Create eye-closed icon
    img_closed = Image.new('RGBA', (16, 16), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img_closed)
    
    # Draw closed eye shape
    draw.line([2, 8, 14, 8], fill=(100, 100, 100, 255), width=1)
    draw.line([2, 8, 14, 8], fill=(100, 100, 100, 255), width=2)
    
    # Save eye-closed icon
    img_closed.save('eye-closed.png', 'PNG')

if __name__ == '__main__':
    create_eye_icons() 