// Freestanding C++ input for the checked-in ELF layout fixtures.
struct Left {
    virtual int left();
};

struct Right {
    virtual int right();
};

struct Derived : Left, Right {
    int left() override;
    int right() override;
};

int Left::left() { return 1; }
int Right::right() { return 2; }
int Derived::left() { return 3; }
int Derived::right() { return 4; }

Derived object;
