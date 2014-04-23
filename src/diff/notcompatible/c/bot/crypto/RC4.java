package diff.notcompatible.c.bot.crypto;

/*
 * Super simple implementation of RC4 ciphering - a bit messy as
 * I just reversed it before I realized it was RC4 (and was unsure if
 * it was modified)
 */
public class RC4 {

	private byte[] state;
	private int x;
	private int y;
	
	public RC4(byte[] key) {
		if(key == null || key.length == 0) {
			throw new NullPointerException();
		}
		
		// initialize state
		state = new byte[0x100];		
		for(int i = 0; i < state.length; i++) {
			state[i] = (byte) i;
		}

		x = 0;
		y = 0;
		int index1 = 0, index2 = 0;
		for(int i = 0; i < state.length; i++) {
			index2 = (((key[index1] & 0xFF) + (state[i] & 0xFF)) + index2) & 0xFF;
			byte tmp = state[i];
			state[i] = state[index2];
			state[index2] = tmp;
			
			index1 = (index1 + 1) % key.length;
		}
	}

	// Originally "decrypt" - used for both forward/backwards though
	public byte[] crypt(byte[] buffer) {
		byte[] result = null;
		
		if(buffer != null) {
			result = new byte[buffer.length];
			
			for(int i = 0; i < buffer.length; i++) {
				x = (x + 1) & 0xFF;
				y = (((state[x] & 0xFF) + y) & 0xFF);
				
				byte tmp = state[x];
				state[x] = state[y];
				state[y] = tmp;
				
				result[i] = (byte) (buffer[i] ^ state[((state[x] & 0xFF) + (state[y] & 0xFF)) & 0xFF]);
			}
		}
			
		return result;
	}
}
