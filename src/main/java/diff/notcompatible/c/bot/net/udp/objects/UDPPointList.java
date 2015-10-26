package diff.notcompatible.c.bot.net.udp.objects;

import java.net.InetSocketAddress;

import diff.notcompatible.c.bot.net.udp.UDPMixer;
import diff.notcompatible.c.bot.net.udp.UDPPoint;
import diff.notcompatible.c.bot.objects.List;

public class UDPPointList {
    private List list;
    private UDPMixer owner;

    public UDPPointList(UDPMixer newOwner) {
        owner = newOwner;
        list = new List();
    }

    public UDPPoint add() {
        UDPPoint point = new UDPPoint(owner);

        list.add(point);

        return point;
    }

    public void add(UDPPoint point) {
        list.add(point);
    }

    public int count() {
        return list.count;
    }

    public UDPPoint getByIndex(int index) {
        return (UDPPoint) list.getObject(index);
    }

    public UDPPoint getByInetSocketAddress(InetSocketAddress socketAddress) {
        for (int i = 0; i < count(); i++) {
            if (((UDPPoint) list.getObject(i)).endPoint.equals(socketAddress)) {
                return (UDPPoint) list.getObject(i);
            }
        }

        return null;
    }

    // Originally GetCondidate
    public int getCandidates() {
        return list.count - getConnection();
    }

    public int getConnection() {
        int candidates = 0;

        for (int i = 0; i < count(); i++) {
            if (((UDPPoint) list.getObject(i)).isEncrypt) {
                candidates++;
            }
        }

        return candidates;
    }

    public void check() {
        for (int i = 0; i < count(); i++) {
            ((UDPPoint) list.getObject(i)).check();
        }
    }

    public void delete(int index) {
        list.delete(list.getObject(index));
    }

    public void delete(UDPPoint point) {
        list.delete(point);
    }
}
