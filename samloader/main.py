# SPDX-License-Identifier: GPL-3.0+
# Copyright (C) 2020 nlscc

import argparse
import os
import sys
import base64
import requests
import xml.etree.ElementTree as ET
from clint.textui import progress

from . import request
from . import crypt
from . import fusclient
from . import versionfetch

def main():
    try:
        parser = argparse.ArgumentParser(description="Download and query firmware for Samsung devices.")
        parser.add_argument("-m", "--dev-model", help="device region code", required=True)
        parser.add_argument("-r", "--dev-region", help="device model", required=True)
        subparsers = parser.add_subparsers(dest="command")
        dload = subparsers.add_parser("download", help="download a firmware")
        dload.add_argument("-v", "--fw-ver", help="firmware version to download", required=True)
        dload.add_argument("-R", "--resume", help="resume an unfinished download", action="store_true")
        dload.add_argument("-M", "--show-md5", help="print the expected MD5 hash of the downloaded file", action="store_true")
        dload_out = dload.add_mutually_exclusive_group(required=False)
        dload_out.add_argument("-O", "--out-dir", help="output the server filename to the specified directory")
        dload_out.add_argument("-o", "--out-file", help="output to the specified file")
        chkupd = subparsers.add_parser("checkupdate", help="check for the latest available firmware version")
        decrypt = subparsers.add_parser("decrypt", help="decrypt an encrypted firmware")
        decrypt.add_argument("-v", "--fw-ver", help="encrypted firmware version", required=True)
        decrypt.add_argument("-V", "--enc-ver", type=int, choices=[2, 4], default=4, help="encryption version (default 4)")
        decrypt.add_argument("-i", "--in-file", help="encrypted firmware file input", required=True)
        decrypt.add_argument("-o", "--out-file", help="decrypted firmware file output", required=True)
        mkfw = subparsers.add_parser("mkfw", help="download and decrypt enc4/enc2 files")
        mkfw.add_argument("-v", "--fw-ver", help="firmware version to download and decrypt", required=True)
        mkfw.add_argument("-R", "--resume", help="resume an unfinished download", action="store_true")
        mkfw.add_argument("-M", "--show-md5", help="print the expected MD5 hash of the downloaded file", action="store_true")
        mkfw.add_argument("-o", "--out-file", help="output to the specified file")
        latest = subparsers.add_parser("latest", help="fetch and decrypt latest firmware file")
        latest.add_argument("-R", "--resume", help="resume an unfinished download", action="store_true")
        latest.add_argument("-M", "--show-md5", help="print the expected MD5 hash of the downloaded file", action="store_true")
        args = parser.parse_args()
        try: args.fw_ver
        except AttributeError: args.fw_ver = None
        if args.fw_ver is not None:
            args.fw_ver = args.fw_ver.upper()
        args.dev_model = args.dev_model.upper()
        args.dev_region = args.dev_region.upper()
        if args.dev_model[0:3] != 'SM-':
            args.dev_model = 'SM-' + args.dev_model

        if args.command == "latest":
            try:
                args.fw_ver = versionfetch.getlatestver(args.dev_model, args.dev_region)
                print(args.fw_ver)
            except:
                print("{} found for {} in {}.".format(args.fw_ver, args.dev_model, args.dev_region))
                sys.exit(1)
            args.command = "mkfw"

        if args.command == "download" or args.command == "mkfw":
            client = fusclient.FUSClient()
            path, filename, size = getbinaryfile(client, args.fw_ver, args.dev_model, args.dev_region)
            if args.command == "mkfw" or not (args.out_file or args.out_dir):
                out = filename
            else:
                out = args.out_file if args.out_file else os.path.join(args.out_dir, filename)
            try:
                dloffset = os.stat(out).st_size if args.resume else 0
            except FileNotFoundError:
                args.resume = None
                dloffset = 0

            print("resuming" if args.resume else "downloading", filename)
            if dloffset == size:
                print("already downloaded!")
                if args.command == "download":
                    return
            else:
                fd = open(out, "ab" if args.resume else "wb")
                initdownload(client, filename)
                r = client.downloadfile(path+filename, dloffset)
                if args.show_md5 and "Content-MD5" in r.headers:
                    print("MD5:", base64.b64decode(r.headers["Content-MD5"]).hex())
                # TODO: use own progress bar instead of clint
                for chunk in progress.bar(r.iter_content(chunk_size=0x10000), expected_size=((size-dloffset)/0x10000)+1):
                    if chunk:
                        fd.write(chunk)
                        fd.flush()
                fd.close()

        elif args.command == "checkupdate":
            try:
                print(versionfetch.getlatestver(args.dev_model, args.dev_region))
            except:
                print("{} found for {} in {}.".format(args.fw_ver, args.dev_model, args.dev_region))
                sys.exit(1)

        if args.command == "decrypt" or args.command == "mkfw":
            if args.command == "mkfw":
                args.in_file = out
                try: args.out_file
                except AttributeError: args.out_file = None
                if not args.out_file:
                    args.out_file = args.in_file[:-5]
                args.enc_ver = int(args.in_file[-1])
            getkey = crypt.getv4key if args.enc_ver == 4 else crypt.getv2key
            key = getkey(args.fw_ver, args.dev_model, args.dev_region)
            length = os.stat(args.in_file).st_size
            with open(args.in_file, "rb") as inf:
                with open(args.out_file, "wb") as outf:
                    crypt.decrypt_progress(inf, outf, key, length)
            if args.command == "mkfw":
                os.remove(args.in_file)
    except KeyboardInterrupt:
        exit(1)


def initdownload(client, filename):
    req = request.binaryinit(filename, client.nonce)
    resp = client.makereq("NF_DownloadBinaryInitForMass.do", req)

def getbinaryfile(client, fw, model, region):
    try:
        req = request.binaryinform(fw, model, region, client.nonce)
        resp = client.makereq("NF_DownloadBinaryInform.do", req)
        root = ET.fromstring(resp)
        status = int(root.find("./FUSBody/Results/Status").text)
        if status != 200:
            raise
    except requests.HTTPError:
        print("{} for {} in {} not found.".format(fw, model, region))
        sys.exit(1)
    size = int(root.find("./FUSBody/Put/BINARY_BYTE_SIZE/Data").text)
    filename = root.find("./FUSBody/Put/BINARY_NAME/Data").text
    path = root.find("./FUSBody/Put/MODEL_PATH/Data").text
    return path, filename, size
