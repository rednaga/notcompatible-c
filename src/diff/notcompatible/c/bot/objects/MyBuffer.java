package diff.notcompatible.c.bot.objects;

import java.nio.ByteBuffer;

public class MyBuffer {

    public int size;
    public ByteBuffer buffer;

    public MyBuffer() {
        size = 0;
        buffer = ByteBuffer.allocate(size);
    }

    public byte[] array() {
        return buffer.array();
    }

    public byte asByte() {
        return buffer.array()[0];
    }

    public int asDWord() {
        byte[] dword = buffer.array();
        return ((dword[3] & 0xFF) << 24) | ((dword[2] & 0xFF) << 16) | ((dword[1] & 0xFF) << 8) | (dword[0] & 0xFF);
    }

    public long asInt64() {
        byte[] int64 = buffer.array();
        return ((int64[7] & 0xFF) << 56) | ((int64[6] & 0xFF) << 48) | ((int64[5] & 0xFF) << 40)
                        | ((int64[4] & 0xFF) << 32) | ((int64[3] & 0xFF) << 24) | ((int64[2] & 0xFF) << 16)
                        | ((int64[1] & 0xFF) << 8) | (int64[0] & 0xFF);
    }

    public int asWord() {
        byte[] word = buffer.array();
        return ((word[1] & 0xFF) << 8) | (word[0] & 0xFF);
    }

    public void clear() {
        buffer = ByteBuffer.allocate(0);
        size = 0;
    }

    public void putDword(int dword) {
        put((byte) (dword & 0xFF));
        put((byte) ((0xFF00 & dword) >> 8));
        put((byte) ((0xFF0000 & dword) >> 16));
        put((byte) ((0xFF000000 & dword) >> 24));
    }

    public void put(byte src) {
        byte[] singleByte = new byte[1];
        singleByte[0] = src;
        putData(singleByte, 0, 1);
    }

    public void put(byte[] src) {
        putData(src, 0, src.length);
    }

    public void put(byte[] src, int srcSize) {
        putData(src, 0, srcSize);
    }

    public void put(String string) {
        put(string.getBytes());
    }

    public void putIP(String ip) {
        String[] x = ip.split("\\.", 4);
        put((byte) (Integer.parseInt(x[0]) & 0xFF));
        put((byte) (Integer.parseInt(x[1]) & 0xFF));
        put((byte) (Integer.parseInt(x[2]) & 0xFF));
        put((byte) (Integer.parseInt(x[3]) & 0xFF));
    }

    public void putData(byte[] src, int srcFrom, int srcSize) {
        ByteBuffer temp = ByteBuffer.allocate(size + srcSize);
        buffer.position(0);

        temp.put(buffer.array());
        byte[] tempBytes = new byte[srcSize];
        System.arraycopy(src, srcFrom, tempBytes, 0, srcSize);
        temp.put(tempBytes);

        buffer = temp;
        size += srcSize;
    }

    public void shift(int shiftBy) {
        ByteBuffer tempBuffer = ByteBuffer.allocate(size - shiftBy);
        byte[] temp = new byte[size - shiftBy];

        System.arraycopy(buffer.array(), shiftBy, temp, 0, size - shiftBy);
        tempBuffer.put(temp);
        buffer = tempBuffer;
        size = size - shiftBy;
    }

    public void putWord(int data) {
        put((byte) (data & 0xFF));
        put((byte) (0xFF00 & data));
    }

    public void putPort(long port) {
        put((byte) ((0xFF00 & port) >> 8));
        put((byte) (port & 0xFF));
    }

    public void putInt64(long data) {
        put((byte) ((int) (0xFFL & data)));
        put((byte) ((int) ((0xFF00L & data) >> 8)));
        put((byte) ((int) ((0xFF0000L & data) >> 16)));
        put((byte) ((int) ((0xFF000000L & data) >> 24)));
        put((byte) ((int) ((0xFF00000000L & data) >> 32)));
        put((byte) ((int) ((0xFF0000000000L & data) >> 40)));
        put((byte) ((int) ((0xFF000000000000L & data) >> 48)));
        put((byte) ((int) ((0xFF00000000000000L & data) >> 56)));
    }

    public byte[] read(int toReadSize) {
        if (size < toReadSize) {
            toReadSize = size;
        }
        byte[] read = new byte[toReadSize];
        System.arraycopy(array(), 0, read, 0, toReadSize);
        shift(toReadSize);

        return read;
    }

}
