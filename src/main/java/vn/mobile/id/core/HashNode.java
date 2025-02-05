//package vn.mobileid.core;
//
//import src.comparator.HashComparator;
//import src.comparator.HashNodeComparator;
//import src.util.Utility;
//
//import java.security.NoSuchAlgorithmException;
//import java.util.ArrayList;
//
//public class HashNode {
//    private byte[] hash;
//    private HashNode parent = null;
//    private ArrayList<HashNode> children = new ArrayList<>();
//    private final String digestMethodOID;
//
//    public HashNode(String digestMethodOID) {
//        this.digestMethodOID = digestMethodOID;
//    }
//
//    public HashNode(byte[] hash, String digestMethodOID) {
//        this.hash = hash;
//        this.digestMethodOID = digestMethodOID;
//    }
//
//    // Getter and Setter
//
//    public void setChildren(ArrayList<HashNode> children) {
//        this.children = children;
//    }
//
//    public void addChildren(HashNode child) {
//        this.children.add(child);
//        child.setParent(this);
//    }
//
//    public ArrayList<HashNode> getChildren() {
//        return this.children;
//    }
//
//    public HashNode getParent() {
//        return this.parent;
//    }
//
//    public void setParent(HashNode parent) {
//        this.parent = parent;
//    }
//
//    public byte[] getHash() {
//        return this.hash;
//    }
//
//    public void setHash() throws NoSuchAlgorithmException {
//        if (!children.isEmpty()) {
//            ArrayList<byte[]> list = new ArrayList<>();
//            for (HashNode h : this.children) {
//                h.setHash();
//                list.add(h.getHash());
//            }
//            list.sort(new HashComparator());
//            this.hash = Utility.groupHashing(list, this.digestMethodOID);
//        }
//    }
//}
