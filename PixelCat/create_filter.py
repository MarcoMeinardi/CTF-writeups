from PIL import Image

doggo = Image.open ("doggo.png")
height = (1900 * doggo.height / doggo.width) ** 0.5
width = 1900 / height
doggo = doggo.resize ((int (width), int (height)))


doggo_filter = Image.new ("RGBA", (128, 128), (0,0,0,0))
doggo_filter.paste (doggo, (128 // 2 - doggo.width // 2, 128 // 2 - doggo.height // 2))
doggo_filter.save ("doggo_filter.png")