package com.beerphilipp.util;

import java.util.ArrayList;
import java.util.Iterator;

public class IteratorUtil {

    public static <T> ArrayList<T> iteratorToArrayList(Iterator<T> iterator) {
        ArrayList<T> list = new ArrayList<>();
        while (iterator.hasNext()) {
            list.add(iterator.next());
        }
        return list;
    }
}
