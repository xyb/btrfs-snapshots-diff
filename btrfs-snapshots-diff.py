#! /usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
""" btrfs-snapshots-diff

Displays differences in 2 Btrfs snapshots (from the same subvolume
obviously).
Uses btrfs send to compute the differences, decodes the stream and
displays the differences.
Can read data from parent and current snapshots, or from diff
file created with:
btrfs send -p parent chid --no-data -f /tmp/snaps-diff


Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


Copyright (c) 2016-2021 Jean-Denis Girard <jd.girard@sysnux.pf>
© SysNux http://www.sysnux.pf/
"""
import argparse
import subprocess
import time
from collections import OrderedDict
from enum import Enum
from os import unlink
from struct import unpack
from sys import exit
from sys import stderr

printerr = stderr.write

BTRFS_SEND_STREAM_MAGIC = b"btrfs-stream"

# From <kernel>/fs/btrfs/send.h
class SendCmd(Enum):
    BTRFS_SEND_C_UNSPEC = 0
    # Version 1
    BTRFS_SEND_C_SUBVOL = 1
    BTRFS_SEND_C_SNAPSHOT = 2
    BTRFS_SEND_C_MKFILE = 3
    BTRFS_SEND_C_MKDIR = 4
    BTRFS_SEND_C_MKNOD = 5
    BTRFS_SEND_C_MKFIFO = 6
    BTRFS_SEND_C_MKSOCK = 7
    BTRFS_SEND_C_SYMLINK = 8
    BTRFS_SEND_C_RENAME = 9
    BTRFS_SEND_C_LINK = 10
    BTRFS_SEND_C_UNLINK = 11
    BTRFS_SEND_C_RMDIR = 12
    BTRFS_SEND_C_SET_XATTR = 13
    BTRFS_SEND_C_REMOVE_XATTR = 14
    BTRFS_SEND_C_WRITE = 15
    BTRFS_SEND_C_CLONE = 16
    BTRFS_SEND_C_TRUNCATE = 17
    BTRFS_SEND_C_CHMOD = 18
    BTRFS_SEND_C_CHOWN = 19
    BTRFS_SEND_C_UTIMES = 20
    BTRFS_SEND_C_END = 21
    BTRFS_SEND_C_UPDATE_EXTENT = 22
    # Version 2
    BTRFS_SEND_C_FALLOCATE = 23
    BTRFS_SEND_C_FILEATTR = 24
    BTRFS_SEND_C_ENCODED_WRITE = 25
    # Version 3
    BTRFS_SEND_C_ENABLE_VERITY = 26


class SendAttr(Enum):
    BTRFS_SEND_A_UNSPEC = 0
    # Version 1
    BTRFS_SEND_A_UUID = 1
    BTRFS_SEND_A_CTRANSID = 2
    BTRFS_SEND_A_INO = 3
    BTRFS_SEND_A_SIZE = 4
    BTRFS_SEND_A_MODE = 5
    BTRFS_SEND_A_UID = 6
    BTRFS_SEND_A_GID = 7
    BTRFS_SEND_A_RDEV = 8
    BTRFS_SEND_A_CTIME = 9
    BTRFS_SEND_A_MTIME = 10
    BTRFS_SEND_A_ATIME = 11
    BTRFS_SEND_A_OTIME = 12
    BTRFS_SEND_A_XATTR_NAME = 13
    BTRFS_SEND_A_XATTR_DATA = 14
    BTRFS_SEND_A_PATH = 15
    BTRFS_SEND_A_PATH_TO = 16
    BTRFS_SEND_A_PATH_LINK = 17
    BTRFS_SEND_A_FILE_OFFSET = 18
    BTRFS_SEND_A_DATA = 19
    BTRFS_SEND_A_CLONE_UUID = 20
    BTRFS_SEND_A_CLONE_CTRANSID = 21
    BTRFS_SEND_A_CLONE_PATH = 22
    BTRFS_SEND_A_CLONE_OFFSET = 23
    BTRFS_SEND_A_CLONE_LEN = 24
    # Version 2
    BTRFS_SEND_A_FALLOCATE_MODE = 25
    BTRFS_SEND_A_FILEATTR = 26
    BTRFS_SEND_A_UNENCODED_FILE_LEN = 27
    BTRFS_SEND_A_UNENCODED_LEN = 28
    BTRFS_SEND_A_UNENCODED_OFFSET = 29
    BTRFS_SEND_A_COMPRESSION = 30
    BTRFS_SEND_A_ENCRYPTION = 31
    # Version 3
    BTRFS_SEND_A_VERITY_ALGORITHM = 32
    BTRFS_SEND_A_VERITY_BLOCK_SIZE = 33
    BTRFS_SEND_A_VERITY_SALT_DATA = 34
    BTRFS_SEND_A_VERITY_SIG_DATA = 35


class BtrfsStreamParser:
    """Btrfs send stream parser"""

    # From btrfs/ioctl.h:#define BTRFS_UUID_SIZE 16
    BTRFS_UUID_SIZE = 16

    # Headers length
    l_head = 10
    l_tlv = 4

    def __init__(self, stream_file, delete=False):

        # Read send stream
        self.stream = stream_file.read()

        if delete:
            try:
                unlink(stream_file)
            except OSError:
                printerr('Warning: could not delete stream file "{stream_file}"\n')

        if len(self.stream) < 17:
            printerr("Invalid stream length\n")
            self.version = None

        magic, _, self.version = unpack("<12scI", self.stream[0:17])
        if magic != BTRFS_SEND_STREAM_MAGIC:
            printerr("Not a Btrfs stream!\n")
            self.version = None

    def _tlv_get(self, attr_type, index):
        attr, l_attr = unpack("<HH", self.stream[index : index + self.l_tlv])
        if SendAttr(attr).name != attr_type:
            raise ValueError(f"Unexpected attribute {SendAttr(attr).name}")
        ret = unpack(
            f"<{l_attr}B",
            self.stream[index + self.l_tlv : index + self.l_tlv + l_attr],
        )
        return index + self.l_tlv + l_attr, ret

    def _tlv_get_string(self, attr_type, index):
        attr, l_attr = unpack("<HH", self.stream[index : index + self.l_tlv])
        if SendAttr(attr).name != attr_type:
            raise ValueError(f"Unexpected attribute {SendAttr(attr).name}")
        (ret,) = unpack(
            f"<{l_attr}s",
            self.stream[index + self.l_tlv : index + self.l_tlv + l_attr],
        )
        return index + self.l_tlv + l_attr, ret.decode("utf8")

    def _tlv_get_u64(self, attr_type, index):
        attr, l_attr = unpack("<HH", self.stream[index : index + self.l_tlv])
        if SendAttr(attr).name != attr_type:
            raise ValueError(f"Unexpected attribute {SendAttr(attr).name}")
        (ret,) = unpack(
            "<Q",
            self.stream[index + self.l_tlv : index + self.l_tlv + l_attr],
        )
        return index + self.l_tlv + l_attr, ret

    def _tlv_get_uuid(self, attr_type, index):
        attr, l_attr = unpack("<HH", self.stream[index : index + self.l_tlv])
        if SendAttr(attr).name != attr_type:
            raise ValueError(f"Unexpected attribute {SendAttr(attr).name}")
        ret = unpack(
            f"<{self.BTRFS_UUID_SIZE}B",
            self.stream[index + self.l_tlv : index + self.l_tlv + l_attr],
        )
        return index + self.l_tlv + l_attr, "".join(["%02x" % x for x in ret])

    def _tlv_get_timespec(self, attr_type, index):
        attr, l_attr = unpack("<HH", self.stream[index : index + self.l_tlv])
        if SendAttr(attr).name != attr_type:
            raise ValueError(f"Unexpected attribute {SendAttr(attr).name}")
        sec, nanos = unpack(
            "<QL",
            self.stream[index + self.l_tlv : index + self.l_tlv + l_attr],
        )
        return index + self.l_tlv + l_attr, float(sec) + nanos * 1e-9

    def parse(self, bogus=True):
        """Decodes commands + attributes from send stream"""
        offset = 17
        cmd_ref = 0

        while True:

            # 3rd field is CRC, not used here
            l_cmd, cmd, _ = unpack("<IHI", self.stream[offset : offset + self.l_head])
            try:
                command = SendCmd(cmd).name
            except IndexError:
                raise ValueError(f"Unknown command {cmd}")

            cmd_short = command[13:].lower()
            offset += self.l_head

            if cmd == SendCmd.BTRFS_SEND_C_RENAME.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, path_to = self._tlv_get_string("BTRFS_SEND_A_PATH_TO", offset2)
                if bogus:
                    # Add bogus renamed_from command on destination to keep track
                    # of what happened
                    yield {
                        "command": "renamed_from",
                        "path": path,
                        "path_to": path_to,
                        "bogus": True,
                        "cmd_ref": cmd_ref,
                    }
                    cmd_ref += 1
                yield {
                    "command": cmd_short,
                    "path": path,
                    "path_to": path_to,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_SYMLINK.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, ino = self._tlv_get_u64("BTRFS_SEND_A_INO", offset2)
                offset2, path_link = self._tlv_get_string(
                    "BTRFS_SEND_A_PATH_LINK",
                    offset2,
                )
                yield {
                    "command": cmd_short,
                    "path": path,
                    "path_link": path_link,
                    "inode": ino,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_LINK.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, path_link = self._tlv_get_string(
                    "BTRFS_SEND_A_PATH_LINK",
                    offset2,
                )
                yield {
                    "command": cmd_short,
                    "path": path,
                    "path_link": path_link,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_UTIMES.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, atime = self._tlv_get_timespec("BTRFS_SEND_A_ATIME", offset2)
                offset2, mtime = self._tlv_get_timespec("BTRFS_SEND_A_MTIME", offset2)
                offset2, ctime = self._tlv_get_timespec("BTRFS_SEND_A_CTIME", offset2)
                if self.version >= 2:
                    offset2, otime = self._tlv_get_timespec(
                        "BTRFS_SEND_A_OTIME",
                        offset2,
                    )
                else:
                    otime = 0.0
                yield {
                    "command": cmd_short,
                    "path": path,
                    "atime": atime,
                    "mtime": mtime,
                    "ctime": ctime,
                    "otime": otime,
                    "cmd_ref": cmd_ref,
                }

            elif cmd in [
                SendCmd.BTRFS_SEND_C_MKFILE.value,
                SendCmd.BTRFS_SEND_C_MKDIR.value,
                SendCmd.BTRFS_SEND_C_UNLINK.value,
                SendCmd.BTRFS_SEND_C_RMDIR.value,
            ]:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                yield {"command": cmd_short, "path": path, "cmd_ref": cmd_ref}

            elif cmd in [
                SendCmd.BTRFS_SEND_C_MKFIFO.value,
                SendCmd.BTRFS_SEND_C_MKSOCK.value,
            ]:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, ino = self._tlv_get_u64("BTRFS_SEND_A_INO", offset2)
                offset2, rdev = self._tlv_get_u64("BTRFS_SEND_A_RDEV", offset2)
                offset2, mode = self._tlv_get_u64("BTRFS_SEND_A_MODE", offset2)
                yield {
                    "command": cmd_short,
                    "ino": ino,
                    "path": path,
                    "rdev": rdev,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_TRUNCATE.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, size = self._tlv_get_u64("BTRFS_SEND_A_SIZE", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "to_size": size,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_SNAPSHOT.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, uuid = self._tlv_get_uuid("BTRFS_SEND_A_UUID", offset2)
                offset2, ctransid = self._tlv_get_u64("BTRFS_SEND_A_CTRANSID", offset2)
                offset2, clone_uuid = self._tlv_get_uuid(
                    "BTRFS_SEND_A_CLONE_UUID",
                    offset2,
                )
                offset2, clone_ctransid = self._tlv_get_u64(
                    "BTRFS_SEND_A_CLONE_CTRANSID",
                    offset2,
                )
                yield {
                    "command": cmd_short,
                    "path": path,
                    "uuid": uuid,
                    "ctransid": ctransid,
                    "clone_uuid": clone_uuid,
                    "clone_ctransid": clone_ctransid,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_SUBVOL.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, uuid = self._tlv_get_uuid("BTRFS_SEND_A_UUID", offset2)
                offset2, ctransid = self._tlv_get_u64("BTRFS_SEND_A_CTRANSID", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "uuid": uuid,
                    "ctrans_id": ctransid,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_MKNOD.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, mode = self._tlv_get_u64("BTRFS_SEND_A_MODE", offset2)
                offset2, rdev = self._tlv_get_u64("BTRFS_SEND_A_RDEV", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "mode": mode,
                    "rdev": rdev,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_SET_XATTR.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, xattr_name = self._tlv_get_string(
                    "BTRFS_SEND_A_XATTR_NAME",
                    offset2,
                )
                offset2, xattr_data = self._tlv_get("BTRFS_SEND_A_XATTR_DATA", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "xattr_name": xattr_name,
                    "xattr_data": xattr_data,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_REMOVE_XATTR.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, xattr_name = self._tlv_get_string(
                    "BTRFS_SEND_A_XATTR_NAME",
                    offset2,
                )
                yield {
                    "command": cmd_short,
                    "path": path,
                    "xattr_name": xattr_name,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_WRITE.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, file_offset = self._tlv_get_u64(
                    "BTRFS_SEND_A_FILE_OFFSET",
                    offset2,
                )
                offset2, data = self._tlv_get("BTRFS_SEND_A_DATA", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "file_offset": file_offset,
                    "data": data,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_CLONE.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, file_offset = self._tlv_get_u64(
                    "BTRFS_SEND_A_FILE_OFFSET",
                    offset2,
                )
                offset2, clone_len = self._tlv_get_u64(
                    "BTRFS_SEND_A_CLONE_LEN",
                    offset2,
                )
                offset2, clone_uuid = self._tlv_get_uuid(
                    "BTRFS_SEND_A_CLONE_UUID",
                    offset2,
                )
                offset2, clone_transid = self._tlv_get_u64(
                    "BTRFS_SEND_A_CLONE_TRANSID",
                    offset2,
                )
                offset2, clone_path = self._tlv_get_string(
                    "BTRFS_SEND_A_CLONE_PATH",
                    offset,
                )  # BTRFS_SEND_A_CLONE8PATH
                offset2, clone_offset = self._tlv_get_u64(
                    "BTRFS_SEND_A_CLONE_OFFSET",
                    offset2,
                )
                yield {
                    "command": cmd_short,
                    "path": path,
                    "file_offset": file_offset,
                    "clone_len": clone_len,
                    "clone_uuid": clone_uuid,
                    "clone_transid": clone_transid,
                    "clone_path": clone_path,
                    "clone_offset": clone_offset,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_CHMOD.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, mode = self._tlv_get_u64("BTRFS_SEND_A_MODE", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "mode": mode,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_CHOWN.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, uid = self._tlv_get_u64("BTRFS_SEND_A_UID", offset2)
                offset2, gid = self._tlv_get_u64("BTRFS_SEND_A_GID", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "user_id": uid,
                    "group_id": gid,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_UPDATE_EXTENT.value:
                offset2, path = self._tlv_get_string("BTRFS_SEND_A_PATH", offset)
                offset2, file_offset = self._tlv_get_u64(
                    "BTRFS_SEND_A_FILE_OFFSET",
                    offset2,
                )
                offset2, size = self._tlv_get_u64("BTRFS_SEND_A_SIZE", offset2)
                yield {
                    "command": cmd_short,
                    "path": path,
                    "file_offset": file_offset,
                    "size": size,
                    "cmd_ref": cmd_ref,
                }

            elif cmd == SendCmd.BTRFS_SEND_C_END.value:
                yield {
                    "command": cmd_short,
                    "headers_length": offset,
                    "stream_length": len(self.stream),
                }
                break

            elif cmd == SendCmd.BTRFS_SEND_C_UNSPEC.value:
                yield {"command": cmd_short}

            else:
                # Should not happen!
                # FIXME support version 2 and 3
                raise ValueError(f'Unexpected command "{command}"')

            offset += l_cmd
            cmd_ref += 1

    def decode(self, bogus=True):
        """Decodes commands + attributes from send stream"""
        # List of commands sequentially decoded
        commands = []
        # Modified paths: dict path => [cmd_ref1, cmd_ref2, ...]
        paths = OrderedDict()
        for cmd in self.parse(bogus=bogus):
            commands.append(cmd)
            cmd_short = cmd["command"]
            if cmd_short in ["end", "unspec"]:
                continue
            if cmd_short == "rename":
                path = cmd["path_to"]
            else:
                path = cmd["path"]
            cmd_ref = cmd["cmd_ref"]
            paths.setdefault(path, []).append(cmd_ref)
        return commands, paths


def time_str(epoch):
    """Epoch => string
    1610391575.9802792 => '2021/01/11 08:59:35'"""
    return time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(epoch))


def print_by_paths(paths, commands, filter, csv):

    # Temporary files / dirs / links... created by btrfs send: they are later
    # renamed to definitive files / dirs / links...
    if filter:
        import re  # pylint: disable=import-outside-toplevel

        re_tmp = re.compile(r"o\d+-\d+-0$")

    for path, actions in paths.items():

        if filter and re_tmp.match(path):
            # Don't display files created temporarily and later renamed
            if not (
                commands[actions[0]]["command"] in ("mkfile", "mkdir", "symlink")
                and commands[actions[1]]["command"] == "rename"
            ) and not (
                commands[actions[0]]["command"] == ("renamed_from")
                and commands[actions[1]]["command"] == "rmdir"
            ):
                print(f'{path}\n\t{actions} {"=" * 20}')
            continue

        if path == "":
            path = "__sub_root__"

        prev_action = None
        extents = []
        print_actions = []

        for action in actions:

            cmd = commands[action]
            cmd_short = cmd["command"]

            if prev_action == "update_extent" and cmd_short != "update_extent":
                print_actions.append(
                    "update extents %d -> %d"
                    % (extents[0][0], extents[-1][0] + extents[-1][1]),
                )

            if cmd_short == "renamed_from":
                if filter and re_tmp.match(cmd_short):
                    if prev_action == "unlink":
                        del print_actions[-1]
                        print_actions.append("rewritten")
                    else:
                        print_actions.append("created")
                else:
                    print_actions.append(f'renamed from "{cmd["path"]}"')

            elif cmd_short == "set_xattr":
                print_actions.append(f'xattr {cmd["xattr_name"]} {cmd["xattr_data"]}')

            elif cmd_short == "update_extent":
                extents.append((cmd["file_offset"], cmd["size"]))

            elif cmd_short == "truncate":
                print_actions.append(f'truncate {cmd["to_size"]:d}')

            elif cmd_short == "chown":
                print_actions.append(f'owner {cmd["user_id"]}:{cmd["group_id"]}')

            elif cmd_short == "chmod":
                print_actions.append(f'mode {cmd["mode"]:o}')

            elif cmd_short == "link":
                print_actions.append(f'link to "{cmd["path_link"]}"')

            elif cmd_short == "symlink":
                print_actions.append(
                    f'symlink to "{cmd["path_link"]}" (inode {cmd["inode"]})',
                )

            elif cmd_short in ("unlink", "mkfile", "mkdir", "mkfifo"):
                print_actions.append(cmd_short)

            elif cmd_short == "rename":
                print_actions.append(f'rename to "{cmd["path_to"]}')

            elif cmd_short == "utimes":
                if filter and prev_action == "utimes":
                    # Print only last utimes
                    del print_actions[-1]
                print_actions.append(
                    f'times a={time_str(cmd["atime"])} '
                    f'm={time_str(cmd["mtime"])} '
                    f'c={time_str(cmd["ctime"])}',
                )

            elif cmd_short == "snapshot":
                print_actions.append(
                    f'snapshot: uuid={cmd["uuid"]}, '
                    f'ctransid={cmd["ctransid"]:d}, '
                    f'clone_uuid={cmd["clone_uuid"]}, '
                    f'clone_ctransid={cmd["clone_ctransid"]:d}',
                )

            elif cmd_short == "write":
                print_actions.append("write: from %d" % cmd[1])
                print_actions.append(
                    "data: \n" + "".join([chr(c) for c in cmd[2]]),
                )  # convert bytes to string

            else:
                print_actions.append("{}, {} {}".format(action, cmd, "-" * 20))
            prev_action = cmd_short

            if csv:
                sep = ";"
                esc_sep = "\\" + sep
                print(
                    f"{path.replace(sep, esc_sep)}{sep}"
                    f"{sep.join([a.replace(sep, esc_sep) for a in print_actions])}",
                )
            else:
                print(f"\n{path}")
                for print_action in print_actions:
                    print(f"\t{print_action}")


def main():
    """Main !"""

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Display differences between 2 Btrfs snapshots",
    )
    parser.add_argument(
        "-p",
        "--parent",
        help="parent snapshot (must exists and be readonly)",
    )
    parser.add_argument(
        "-c",
        "--child",
        help="child snapshot (will be created if it does not exist)",
    )
    parser.add_argument("-f", "--file", help="diff file")
    parser.add_argument(
        "-t",
        "--filter",
        action="store_true",
        help=(
            "does not display temporary files, nor all time modifications "
            "(just latest)"
        ),
    )
    parser.add_argument(
        "-a",
        "--by_path",
        action="store_true",
        help="Group commands by path",
    )
    parser.add_argument("-s", "--csv", action="store_true", help="CSV output")
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="JSON output (commands only)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-b",
        "--bogus",
        action="store_true",
        help="Add bogus renamed_from action (used only when grouping by path)",
    )
    #    parser.add_argument('-v', '--verbose', action="count", default=0,
    #                        help="increase verbosity")
    args = parser.parse_args()

    if args.parent:
        if args.child:
            # TODO add option to omit '--no-data'
            stream_file = "/tmp/snaps-diff"
            cmd = [
                "btrfs",
                "send",
                "-p",
                args.parent,
                "--no-data",
                "-f",
                stream_file,
                args.child,
                "-q",
            ]
            try:
                subprocess.check_call(cmd)

            except subprocess.CalledProcessError:
                printerr('Error: CalledProcessError\nexecuting "{' '.join(cmd)}"\n')
                exit(1)
        else:
            printerr("Error: parent needs child!\n")
            parser.print_help()
            exit(1)

    elif args.file is None:
        parser.print_help()
        exit(1)

    else:
        stream_file = args.file

    try:
        f_stream = open(stream_file, "rb")
    except OSError:
        printerr("Error reading stream\n")
        exit(1)

    stream = BtrfsStreamParser(f_stream)

    if stream.version is None:
        exit(1)
    commands, paths = stream.decode(bogus=args.bogus)

    if args.by_path:
        print(f"Found a valid Btrfs stream header, version {stream.version}\n")
        print_by_paths(paths, commands, args.filter, args.csv)

    elif args.csv:
        sep = ";"
        esc_sep = "\\" + sep
        for cmd in commands:
            print(f'{cmd["command"].replace(sep, esc_sep)}', end="")
            for k in sorted(cmd):
                if k == "command":
                    continue
                v = cmd[k]
                if isinstance(v, str):
                    v = v.replace(sep, esc_sep)
                print(f"{sep}{k}={v}", end="")
            print()

    elif args.json:
        import json  # pylint: disable=import-outside-toplevel

        if args.pretty:
            print(json.dumps(commands, indent=2))
        else:
            print(json.dumps(commands))

    else:
        printerr("No output!\n")
        parser.print_help()


if __name__ == "__main__":
    main()
