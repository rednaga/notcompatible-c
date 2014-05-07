package diff.notcompatible.c.bot.objects;

/**
 * Pojo for encapsuling all the servers together
 */
public class ServerGroupList {

    public List list;

    public ServerGroupList() {
        list = new List();
    }

    /**
     * Add a Server to a specific ServerGroup via the groupId
     * 
     * If groupId returns null, a new ServerGroup is created
     * 
     * @param groupId
     * @param server
     */
    public void addServerInGroup(int groupId, Server server) {
        ServerGroup tmp = getByID(groupId);

        if (tmp == null) {
            tmp = new ServerGroup();
            tmp.groupId = groupId;
            list.add(tmp);
        }

        tmp.add(server);
    }

    /**
     * Return a ServerGroup by the groupId (not the true index)
     * 
     * @param groupId
     * @return
     */
    public ServerGroup getByID(int groupId) {
        for (int i = 0; i < list.count; i++) {
            if (((ServerGroup) list.getObject(i)).groupId == groupId) {
                return (ServerGroup) list.getObject(i);
            }
        }

        return null;
    }
}
