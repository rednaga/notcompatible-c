package diff.notcompatible.c.bot.net;

import java.io.IOException;
import java.nio.channels.SelectionKey;

public class CustomSocket {
    public long time_start_connection;

    public CustomSocket() {
        time_start_connection = 0;
    }

    public void onAccept(SelectionKey key) throws IOException {
    	
    }

    public void onClose(SelectionKey key) throws IOException {
    	
    }

    public void onConnect(SelectionKey key) throws IOException {
    	
    }

    public void onNoConnect(SelectionKey key) throws IOException {
    	
    }

    public void onRead(SelectionKey key) throws IOException{
    	
    }

    public void onWrite(SelectionKey key) throws IOException {
    	
    }
}
