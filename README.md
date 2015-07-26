# cryptovid

cryptovid is a proof of concept storing arbitrary binary data in videos.

cryptovid uses [libsodium](https://github.com/jedisct1/libsodium) to
symmetrically encrypt video. It is not meant to be used for public-key
messaging and does not support that at this time.

***This is an unaudited proof of concept and uses unaudited third party
modules. Do not use for protection of life or property, or in
environments hostile to strong encryption.***


### How cryptovid works

cryptovid was inspired by
[youtubefs](https://code.google.com/p/youtubefs/), a FUSE layer for
YouTube. What if you want to write to a video service? Better
yet, what if you wanted to write *anything* to a video service as a
file? You need an abstraction to let it happen.

cryptovid is glue. It takes binary data into memory, encrypts it for
data confidentiality, generates a series of QR codes from it, and
then stitches the QR codes into frames in a video using `ffmpeg`.
This video can then be uploaded to a video service, where data will be
resilient to transcoding thanks to QR code error correction. To read a
file, you need the video and an encryption key. It is split by `ffmpeg`
then read in using Python bindings to `zbar`.

Do not change the QR code or resolution settings. Videos over 720p
failed on testing on some services.


### Setup and installation

For now, you need `ffmpeg` on your `$PATH` and `pip`. If you are on
a newer Ubuntu:

```
# apt-get install -y python-pip libzbar-dev python-dev
# pip install -r requirements.txt
```

If you do not have a package for `ffmpeg` in your distribution, you can
get a late ffmpeg [from ffmpeg directly](http://ffmpeg.org/download.html). It is not bundled with cryptovid due to security concerns.


### Usage

See `cryptovid.py -h`.


### Wishlist

* Audit the PBKDF library
* Buffer video reading
* Use `av` bindings to `libav` vs. calling out to `subprocess`
* Use a faster QRcode encoding library
* Experiment with interlacing as compression; QR codes should be
  resilient to deinterlacing
* Run LZMA or another compression algorithm before data encryption


### License

GNU GPL v3.


### Donate

Please donate to an electronic rights organization like [EFF](https://www.eff.org/), or [teach someone that encryption isn't a bad thing](https://www.schneier.com/blog/archives/2015/06/why_we_encrypt.html).
