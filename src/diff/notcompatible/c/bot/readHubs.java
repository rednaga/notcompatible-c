package diff.notcompatible.c.bot;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import diff.notcompatible.c.bot.objects.HubList;

public class readHubs {

    public static HubList hubList;

    public static void main(String[] args) {
        hubList = new HubList();

        loadList(new File(args[0]));

        System.out.println("Hub List: ");
        printList(hubList);
    }

    public static void printList(HubList list) {
        if (list != null) {
            for (int i = 0; i < list.count(); i++) {
                System.out.println(list.getByIndex(i));
            }
        }
    }

    private static void loadList(File list) {
        try {
            File hubListFile = list;
            if (hubListFile.exists()) {
                InputStream fi = new FileInputStream(hubListFile);
                byte[] buffer = new byte[fi.available()];
                DataInputStream file = new DataInputStream(fi);

                file.read(buffer);
                hubList.loadFromRaw(buffer);
                System.out.println(" [*] Loaded [ " + hubList.count() + " ] hubs");

                file.close();
                fi.close();
            } else {
                System.err.println(" [!] No Hub list found!");
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
