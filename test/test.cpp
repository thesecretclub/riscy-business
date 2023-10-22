struct Blah2
{
    int x;
    int y;
    Blah2(int x, int y) : x(x), y(y) {

    }
};

static Blah2 blah = Blah2(12, 34);
static Blah2 blah2 = Blah2(56, 78);

extern "C" int bb() {
    return blah.x + blah2.y;
}