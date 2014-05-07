package diff.notcompatible.c.bot.net.udp.objects;

import java.net.InetSocketAddress;

public class UDPRemPointListItem {
    public InetSocketAddress addr;
    public int status;

    public UDPRemPointListItem() {
        status = 0;
    }
}