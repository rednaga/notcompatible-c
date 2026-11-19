package diff.notcompatible.c.bot.net;

import java.net.InetSocketAddress;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.objects.Config;
import diff.notcompatible.c.bot.objects.Packet;
import diff.notcompatible.c.bot.objects.Server;
import diff.notcompatible.c.bot.objects.ServerGroup;
import diff.notcompatible.c.bot.objects.ServerGroupList;

// Originally this was "ConectionManager"
public class ConnectionManager {

    private final static Logger LOGGER = Logger.getLogger("session");

    public Config config;
    public int group;
    public int index;
    public int badConnect;
    public ServerGroupList groupServerList;

    public ConnectionManager(Config configuration) {
        config = configuration;
        group = 0;
        index = 0;
        badConnect = 0;
        groupServerList = new ServerGroupList();
    }

    public void load() {
        if (config.packet.getByName("GROUP") != null) {
            group = config.packet.getByName("GROUP").asWord();
        }
        if (config.packet.getByName("INDEXGROUP") != null) {
            index = config.packet.getByName("INDEXGROUP").asDWord();
        }

        // CONFIG -> SET -> DATA -> GROUP -> (ID, SERV | DOM)
        Packet setPacket = config.packet.getByName("SET");
        Packet data = (setPacket != null) ? setPacket.getByName("DATA") : null;
        if (data != null) {
            for (int i = 0; i < data.getCount(); i++) {
                Packet tmp = data.getByIndex(i);
                if (tmp.tag.equals("GROUP")) {
                    int ngr = tmp.getByName("ID").asWord();
                    for (int j = 0; j < tmp.getCount(); j++) {
                        Packet tmp2 = tmp.getByIndex(j);
                        if (tmp2.tag.equals("SERV")) {
                            groupServerList.addServerInGroup(ngr, new Server(tmp2.getByName("IP").asIP(), tmp2
                                            .getByName("PORT").asPort()));
                        }
                        if (tmp2.tag.equals("DOM")) {
                            groupServerList.addServerInGroup(ngr, new Server(tmp2.getByName("NAME").asString(),
                                            tmp2.getByName("PORT").asPort()));
                        }
                    }
                }
            }
        }

        // A saved group that is not in the config any more: start over
        if (groupServerList.getByID(group) == null) {
            group = 0;
            index = 0;
        }
    }

    public void connectOk() {
        badConnect = 0;
    }

    public void setGroup(int gr) {
        group = gr;
        index = 0;
    }

    public void setIndex(int indx) {
        index = indx;
    }

    public void connectBad() {
        badConnect++;
        if ((badConnect % 10) == 0) {
            index++;
        }
        if (badConnect > 60) {
            group = 0;
        }
        if (badConnect > 5000) {
            badConnect = 500;
        }
    }

    public InetSocketAddress getServer() {
        ServerGroup serverGroup = groupServerList.getByID(group);
        // If server group is improperly set, reset it
        if (serverGroup == null) {
            setGroup(0);
            serverGroup = groupServerList.getByID(group);
        }

        if (serverGroup != null) {
            if (serverGroup.count() > 0) {
                // 63d5 (com.core.android.defender) wraps when index >= count. 75da (com.security.patch)
                // has the comparison the other way round ("count >= index") and so never moves past
                // the first server; that is one of the observable differences between the two.
                if (serverGroup.count() <= index) {
                    index = 0;
                }
                LOGGER.info(" [!] Establishing connection to server - " + serverGroup.indexOf(index).server + ":"
                                + serverGroup.indexOf(index).port);
                return new InetSocketAddress(serverGroup.indexOf(index).server, serverGroup.indexOf(index).port);
            }
        }

        return null;
    }

}
