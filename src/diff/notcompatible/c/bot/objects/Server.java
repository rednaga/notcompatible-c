package diff.notcompatible.c.bot.objects;

/**
 * Pojo for server/port
 */
public class Server {
    public int port;
    public String server;

    public Server(String asString, int asWord) {
        server = asString;
        port = asWord;
    }
}
