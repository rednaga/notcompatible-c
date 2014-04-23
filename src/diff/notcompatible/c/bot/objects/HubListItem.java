package diff.notcompatible.c.bot.objects;

public class HubListItem {
	
	public long lastConnect;
	public long lastTested;
	public boolean used;
	public int status;
	public long upTime;
	public String ip;
	public long port;
	public long connectCount;
	
	
	HubListItem() {
		ip = "";
		port = 0;
		lastConnect = 0;
		lastTested = 0;
		upTime = 0;
		connectCount = 0;
		used = false;
		status = 0;
	}


	@Override
	public String toString() {
		return "HubListItem [lastConnect=" + lastConnect + ", lastTested="
				+ lastTested + ", upTime=" + upTime + ", ip=" + ip + ", port="
				+ port + ", connectCount=" + connectCount + ", status="
				+ status + ", used=" + used + "]";
	}
}
