package diff.notcompatible.c.bot;

public class udpThreadServer extends ThreadServer {

	public udpThreadServer(Object ownerObject) {
		super(ownerObject);
		// TODO Auto-generated constructor stub
	}

	@Override
	public void createP2PListen() {
		// Let's ignore P2P stuff in this bot
	}
}
