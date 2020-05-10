# Merkle Mountain Range

## Preamble

Merkle Mountain Ranges [[link](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md)] are an alternative to Merkle tree. While the latter relies on perfectly balanced binary trees, the former can be seen either as list of perfectly balance binary trees or a single binary tree that would have been truncated from the top right. 

A Merkle Mountain Range (MMR) is strictly append-only: elements are added from the left to the right, adding a parent as soon as 2 children exist, filling up the range accordingly.

## Example
An example of this merkle forest woule be:  
```
 /\
/\/\/\
```
This can be seen as:
```
0
00
001 <- indexes 0 and 1 are hashed to form index 2
0010
0010012 <- another tree, which leads to the two subtrees being merged (height 2)
00100120
0010012001 <- now we have two trees, one of height 2, one of height 1
```

## Bagging

Now we have several trees (like a forest), how to collect them to create a merkle root then?