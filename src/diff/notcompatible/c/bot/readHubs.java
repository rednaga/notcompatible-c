package diff.notcompatible.c.bot;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import diff.notcompatible.c.bot.objects.HubList;

public class readHubs {
	
	public static HubList hubList;
	public static HubList udpList;
	
	public static void main(String[] args) {
		hubList = new HubList();
		udpList = new HubList();
		
		loadHubList();
		loadUDPHubList();
		
		System.out.println("Hub List: ");
		printList(hubList);
		
		System.out.println("");
		
		System.out.println("UDP Hub List: ");
		printList(udpList);
	}
	
	public static void printList(HubList list) {
		if(list != null) {
			for(int i = 0; i < list.count(); i++) {
				System.out.println(list.getByIndex(i));
			}
		}
	}
	
	private static void loadHubList() {
        try {
        	File hubListFile = new File("hl.bin");
        	if(hubListFile.exists()) {
	            InputStream fi = new FileInputStream(hubListFile);
	            byte[] buffer = new byte[fi.available()];
	            DataInputStream file = new DataInputStream(fi);
	
	            file.read(buffer);
				hubList.loadFromRaw(buffer);
	            System.out.println(" [*] Loaded [ " + hubList.count() + " ] hubs");
	            
	            file.close();
	            fi.close();
        	} else {
            	System.err.println(" [!] No Hub list found - likely never created!");
        	}
        } catch (Exception exception) {
			exception.printStackTrace();
        }
	}
	
	// Gets local "uhl.bin"
	private static void loadUDPHubList() {
        try {
        	File udpHubListFile = new File("uhl.bin");
        	if(udpHubListFile.exists()) {
	            InputStream fi = new FileInputStream(udpHubListFile);
	            byte[] buffer = new byte[fi.available()];
	            DataInputStream file = new DataInputStream(fi);
	
	            file.read(buffer);
	            udpList.loadFromRaw(buffer);
	            System.out.println(" [*] Loaded [ " + udpList.count() + " ] hubs");
	            
	            file.close();
	            fi.close();
        	} else {
            	System.err.println(" [!] No UDP Hub list found - likely never created!");
        	}
        } catch (Exception exception) {
			exception.printStackTrace();
        }
	}
}
