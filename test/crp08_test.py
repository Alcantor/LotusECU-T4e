from platform import uname

from lib import crp08
from tempfile import TemporaryDirectory


def test_crp08_t6_pack_unpack(IMAGE_TYPE=1):
    BIN_FILE="test_data/crp08/random_BIN.cpt"
    TAB_FILE="test_data/crp08/random_TAB.cpt"
    # pack two random files and ensure that they unpack correctly
    crp = crp08.CRP08()
    crp.add_cal(TAB_FILE, IMAGE_TYPE)
    crp.add_prog(BIN_FILE, IMAGE_TYPE)

    with TemporaryDirectory() as td:
        outfn = f"{td}/output.crp"
        crp.write_file(outfn)

        # verify that the file was written correctly
        unpack_crp = crp08.CRP08()
        unpack_crp.read_file(outfn, IMAGE_TYPE)

        assert len(unpack_crp.chunks) == 3

        toc = unpack_crp.chunks[0].toc_values[0]
        assert len(toc) == 2, "Invalid table of content length"

        assert crp.chunks[1].data == unpack_crp.chunks[1].data
        assert crp.chunks[2].data == unpack_crp.chunks[2].data

