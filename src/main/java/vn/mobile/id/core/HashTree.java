//package src.hashtree;
//
//import eu.europa.esig.dss.enumerations.DigestAlgorithm;
//import eu.europa.esig.dss.spi.DSSUtils;
//
//import java.nio.charset.StandardCharsets;
//import java.security.NoSuchAlgorithmException;
//import java.util.ArrayList;
//
//public class HashTree {
//    private HashNode root;
//    private ArrayList<HashNode> leaves = new ArrayList<>();
//    private final String digestMethodOID;
//
//    private final byte[] baseHash;
//
//    public HashTree(String digestMethodOID) throws NoSuchAlgorithmException {
//        this.digestMethodOID = digestMethodOID;
//        DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(digestMethodOID);
//        this.baseHash = DSSUtils.digest(digestAlgorithm, "bweh".getBytes(StandardCharsets.UTF_8));
//    }
//
//    // Getter and Setter
//
//    public ArrayList<HashNode> getLeaves() {
//        return this.leaves;
//    }
//
//    public void setLeaves(ArrayList<HashNode> leaves) {
//        this.leaves = leaves;
//    }
//
//    public String getDigestMethodOID() {
//        return this.digestMethodOID;
//    }
//
//    public HashNode getRoot() {
//        return this.root;
//    }
//
//    // Algorithm
//
//    public void buildTree(ArrayList<HashNode> nodeList, int groupSize, int overhead) throws NoSuchAlgorithmException {
//        if (overhead == 0) return;
//
//        if (nodeList.size() == 1) {
//            this.root = nodeList.getFirst();
//            this.root.setHash();
//            return;
//        }
//        int groupCount = (nodeList.size() + groupSize - 1) / groupSize;
//        ArrayList<HashNode> nextGroup = new ArrayList<>();
//        for (int group = 0; group < groupCount; group += 1) {
//            nextGroup.add(new HashNode(this.digestMethodOID));
//            for (int member = 0; member < groupSize; member += 1) {
//                int p = group * groupSize + member;
//                if (p >= nodeList.size()) continue;
//                nextGroup.get(group).addChildren(nodeList.get(p));
//            }
//        }
//        this.buildTree(nextGroup, groupSize, overhead - 1);
//    }
//}
