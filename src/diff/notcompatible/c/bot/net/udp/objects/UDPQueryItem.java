package diff.notcompatible.c.bot.net.udp.objects;

import diff.notcompatible.c.bot.net.udp.UDPQuery;
import diff.notcompatible.c.bot.objects.List;
import diff.notcompatible.c.bot.objects.MyBuffer;

public class UDPQueryItem {
    private List frag;
    private UDPQuery owner;
    public int seq;
    public int totalCount;
    public long lastChangeTime;

    public UDPQueryItem(UDPQuery newOwner) {
        seq = 0;
        lastChangeTime = 0;
        totalCount = 0;
        owner = newOwner;
        frag = new List();
    }

    private UDPQueryItemData getPart(int part) {
    	for(int i = 0; i < frag.count; i++)
    		if(((UDPQueryItemData) frag.getObject(i)).part == part)
    			return (UDPQueryItemData) frag.getObject(i);

    	return null;
    }

    public void put(int part, byte[] data) {
        if (getPart(part) == null) {
            lastChangeTime = System.currentTimeMillis();
            UDPQueryItemData dt = new UDPQueryItemData();
            dt.part = part;
            dt.data = data;
            frag.add(dt);
            MyBuffer mb = new MyBuffer();
            
            for(int i = 1; i <= totalCount; i++) {
                dt = getPart(i);
                if (dt != null)
                    mb.put(dt.data);
            }
            
            owner.fullSeq(this, mb.array());
        }
    }
    
    class UDPQueryItemData {
        byte[] data;
        int part;

        UDPQueryItemData() {
        }
    }
}
