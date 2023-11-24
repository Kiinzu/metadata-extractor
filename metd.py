from PIL import Image, ExifTags
from PIL.ExifTags import TAGS
from iptcinfo3 import IPTCInfo
from pwn import *

iptc_mapping = {
    20: 'supplemental category',
    25: 'keywords',
    118: 'contact',
    55: 'date created',
    60: 'time created',
    90: 'city',
    95: 'province/state',
    101: 'country/primary location name',
    100: 'country/primary location code',
    5: 'object name',
    15: 'category',
    7: 'edit status',
    80: 'by-line',
    85: 'by-line title',
    110: 'credit',
    115: 'source',
    122: 'writer/editor',
    120: 'caption/abstract',
    105: 'headline',
    40: 'special instructions',
    103: 'original transmission reference',
    10: 'urgency',
    116: 'copyright notice',
    92: 'sub-location',
    221: 'nonstandard_221',
    62: 'digital creation date',
    63: 'digital creation time',
}

def extract_exif(image_path):
    try:
        with Image.open(image_path) as img:
            exif_data ={
                ExifTags.TAGS[k]: v
                for k, v in img._getexif().items()
                if k in ExifTags.TAGS
            }
            print()
            log.success("=====================================================EXIF Metadata=====")
            if exif_data:
                if 'GPSInfo' in exif_data:
                    latitude_degrees = exif_data['GPSInfo'][2][0].numerator
                    latitude_minutes = exif_data['GPSInfo'][2][1].numerator
                    latitude_seconds = exif_data['GPSInfo'][2][2].numerator / exif_data['GPSInfo'][2][2].denominator
                    latitude_direction = exif_data['GPSInfo'][1]

                    longitude_degrees = exif_data['GPSInfo'][4][0].numerator
                    longitude_minutes = exif_data['GPSInfo'][4][1].numerator
                    longitude_seconds = exif_data['GPSInfo'][4][2].numerator / exif_data['GPSInfo'][4][2].denominator
                    longitude_direction = exif_data['GPSInfo'][3]

                    geo_coordinate = '{0} {1} {2:.2f} {3}, {4} {5} {6:.2f} {7}'.format(
                        latitude_degrees, latitude_minutes, latitude_seconds, latitude_direction,
                        longitude_degrees, longitude_minutes, longitude_seconds, longitude_direction
                    )

                    print("GPSInfo - Coordinate:", geo_coordinate)
                for tags,value in exif_data.items():
                    if tags == 'GPSInfo':
                        continue
                    else:
                        print(f'{tags} : {value}')
            else:
                log.info(f"No Exif metadata found on {image_path} ")
    except Exception as e:
        print(f"Error: {e}")

def extract_xmp(image_path):
    try:
        with Image.open(image_path) as img:
            xmp_data = img.getxmp()
            if xmp_data:
                print()
                log.success("======================================================XMP Metadata=====")
                for key,value in xmp_data.items():
                    print(f'{key} : {value}')
            else:
                log.info(f"No XMP Metadata Found on {image_path}")
    except Exception as e:
        print(f"Error: {e}")

def extract_itpc(image_path):
    info = IPTCInfo("./all.jpg", force=True, inp_charset='utf8')
    if info:
        print()
        log.success("======================================================IPTC Metadata====")
        for tegs, name in sorted(iptc_mapping.items()):
            value = info[tegs]
            if isinstance(value,list):
                print(f"{name}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{name}: {value}")
    else:
        log.info(f"No IPTC Metadata Found on {image_path}")

def rapiin_aja():
    print("=======================================================================")

if __name__=="__main__":
    imagepath = input("Which Image: ").strip()
    extract_exif(imagepath)
    extract_xmp(imagepath)
    extract_itpc(imagepath)
    rapiin_aja()