package diff.notcompatible.c.bot.objects.sort;

import diff.notcompatible.c.bot.objects.HubListItem;

public class HubListSortConnected extends ListSortCompare {
	
	public HubListSortConnected() {

	}
	
    public int sortFunction(Object object1, Object object2) {
        HubListItem a = (HubListItem) object2;
        HubListItem b = (HubListItem) object2;
        
        if (a.lastConnect > b.lastConnect) {
            return 1;
        } else if (a.lastConnect < b.lastConnect) {
            return -1;
        }
        
        return 0;
    }
}
