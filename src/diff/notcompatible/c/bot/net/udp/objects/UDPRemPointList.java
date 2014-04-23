package diff.notcompatible.c.bot.net.udp.objects;

import java.net.InetSocketAddress;

import diff.notcompatible.c.bot.objects.List;

public class UDPRemPointList {
	
	    private List list;

	    public UDPRemPointList() {
	        list = new List();
	    }

	    public void add(InetSocketAddress addr) {
	    	UDPRemPointListItem item = new UDPRemPointListItem();
	        item.addr = addr;
	        list.add(item);
	    }

	    // originally CondidateCount
	    public int candidateCount() {
	    	int candidates = 0;
	    	
	    	for(int i = 0; i < count(); i++)
	    		if(((UDPRemPointListItem) list.getObject(i)).status == 0)
	    			candidates++;
	    	
	    	return candidates;
	    }

	    public int count() {
	        return list.count;
	    }

	    public void delete(int index) {
	        list.delete(list.getItem(index));
	    }

	    public void delete(UDPRemPointListItem item) {
	        list.delete(item);
	    }

	    public UDPRemPointListItem getCandidate() {
	    	for(int i = 0; i < count(); i++)
	    		if(((UDPRemPointListItem) list.getObject(i)).status == 0)
	    			return (UDPRemPointListItem) list.getObject(i);
	    	
	    	return null;
	    }


	    public UDPRemPointListItem indexOf(InetSocketAddress addr) {
	    	for(int i = 0; i < count(); i++)
	    		if(((UDPRemPointListItem) list.getObject(i)).addr.equals(addr))
	    			return (UDPRemPointListItem) list.getObject(i);
	    	
	    	return null;
	    }
	
}
