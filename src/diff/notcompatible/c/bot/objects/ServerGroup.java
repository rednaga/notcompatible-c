package diff.notcompatible.c.bot.objects;

/**
 * Pojo for grouping servers together inside lists
 */
public class ServerGroup {
    public int groupId;
    public List serverList;

    public ServerGroup() {
        serverList = new List();
    }

    public void add(Server svr) {
        serverList.add(svr);
    }

    public int count() {
        return serverList.count;
    }

    public void delete(int index) {
        serverList.delete(serverList.getObject(index));
    }

    public Server indexOf(int index) {
        return (Server) serverList.getObject(index);
    }
}
