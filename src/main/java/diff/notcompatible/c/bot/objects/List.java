package diff.notcompatible.c.bot.objects;

import diff.notcompatible.c.bot.objects.sort.ListSortCompare;

public class List {

    public int count;
    public Item head;
    public Item last;

    public List() {
        head = last = null;
        count = 0;
    }

    public void add(Object toAdd) {
        Item item = new Item();
        item.object = toAdd;
        if (head != null) {
            last.next = item;
            last = item;
            count++;
        } else {
            // first item
            head = last = item;
            count++;
        }
    }

    public void clear() {
        head = null;
        last = null;
        count = 0;
    }

    public Object getObject(int index) {
        if (getItem(index) != null) {
            return getItem(index).object;
        }

        return null;
    }

    public Item getItem(int index) {
        Item item = null;

        if (head != null) {
            int current = 0;
            Item currentItem = head;
            while (current != index) {
                currentItem = currentItem.next;
                current++;
            }
            item = currentItem;
        }

        return item;
    }

    public void delete(Object toDelete) {
        if ((count != 0) && (toDelete != null)) {
            Item headItem = head;
            Item previousItem = null;
            while (headItem != null) {
                if (headItem.object == toDelete) {
                    if (previousItem == null) {
                        head = headItem.next;
                    } else {
                        if (headItem.next != null) {
                            previousItem.next = headItem.next;
                        } else {
                            last = previousItem;
                            previousItem.next = null;
                        }
                    }
                    count--;
                    if (count == 0) {
                        last = null;
                    }
                }
                previousItem = headItem;
                headItem = headItem.next;
            }
        }
    }

    public Item findObject(Object object) {
        if (count != 0) {
            Item postion = head;
            while (postion != null) {
                if (postion.object != object) {
                    postion = postion.next;
                } else {
                    return postion;
                }
            }
        }

        return null;
    }

    /**
     * Swap (objects)
     */
    public void swap(int i, int j) {
        Item i1 = getItem(i);
        Item j1 = getItem(j);

        Object o1 = i1.object;
        i1.object = j1.object;
        j1.object = o1;
    }

    public void sort(ListSortCompare listSortCompare) {
        if (count > 2) {
            prSort(listSortCompare, 0, count - 1);
        }
    }

    // TODO: Clean
    public void prSort(ListSortCompare listSortCompare, int l, int r) {
        int i = l;
        int j = r;
        Object x = getObject((l + r) / 2);
        while (true) {
            if (listSortCompare.sortFunction(getObject(i), x) != 1) {
                while (listSortCompare.sortFunction(getObject(j), x) == -1) {
                    j--;
                }
                if (i <= j) {
                    swap(j, i);
                    i++;
                    j--;
                }
                if (i > j) {
                    if (l < j) {
                        prSort(listSortCompare, l, j);
                    }
                    if (i < r) {
                        prSort(listSortCompare, i, r);
                    }
                    return;
                }
            } else {
                i++;
            }
        }
    }

}
