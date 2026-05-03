import skimage.io as io

img1 = io.imread('CTF_DATA/CTF2/Layer1.png')
img2 = io.imread('CTF_DATA/CTF2/Layer2.png')
img3 = img1 + img2
io.imshow(img3)
io.show()