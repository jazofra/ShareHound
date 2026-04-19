#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import tempfile
import unittest

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from sharehound.core.StreamingOpenGraph import StreamingOpenGraph


class StreamingOpenGraphTests(unittest.TestCase):
    def _make_node(self, id_: str, kind: str = "Thing") -> Node:
        return Node(id=id_, kinds=[kind], properties=Properties(name=id_))

    def _make_edge(self, start: str, end: str, kind: str = "Has") -> Edge:
        return Edge(start_node=start, end_node=end, kind=kind)

    def test_node_dedup_by_id(self):
        g = StreamingOpenGraph()
        try:
            self.assertTrue(g.add_node_without_validation(self._make_node("a")))
            self.assertFalse(
                g.add_node_without_validation(self._make_node("a", "Different"))
            )
            self.assertEqual(g.get_node_count(), 1)
        finally:
            g.close()

    def test_edge_dedup_by_key(self):
        g = StreamingOpenGraph()
        try:
            g.add_node_without_validation(self._make_node("a"))
            g.add_node_without_validation(self._make_node("b"))
            self.assertTrue(
                g.add_edge_without_validation(self._make_edge("a", "b", "Has"))
            )
            self.assertFalse(
                g.add_edge_without_validation(self._make_edge("a", "b", "Has"))
            )
            self.assertTrue(
                g.add_edge_without_validation(self._make_edge("a", "b", "Other"))
            )
            self.assertEqual(g.get_edge_count(), 2)
        finally:
            g.close()

    def test_validated_add_edge_requires_nodes(self):
        g = StreamingOpenGraph()
        try:
            self.assertFalse(g.add_edge(self._make_edge("a", "b")))
            g.add_node_without_validation(self._make_node("a"))
            self.assertFalse(g.add_edge(self._make_edge("a", "b")))
            g.add_node_without_validation(self._make_node("b"))
            self.assertTrue(g.add_edge(self._make_edge("a", "b")))
        finally:
            g.close()

    def test_export_produces_valid_json(self):
        g = StreamingOpenGraph(source_kind="TestKind")
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        tmp.close()
        try:
            g.add_node_without_validation(self._make_node("a"))
            g.add_node_without_validation(self._make_node("b"))
            g.add_edge_without_validation(self._make_edge("a", "b", "Has"))

            self.assertTrue(g.export_to_file(tmp.name, include_metadata=True))

            with open(tmp.name, "r") as f:
                data = json.load(f)

            self.assertEqual(data["metadata"]["source_kind"], "TestKind")
            self.assertEqual(len(data["graph"]["nodes"]), 2)
            self.assertEqual(len(data["graph"]["edges"]), 1)
            self.assertEqual(data["graph"]["edges"][0]["kind"], "Has")
        finally:
            g.close()
            os.unlink(tmp.name)

    def test_export_empty_graph(self):
        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        tmp.close()
        try:
            self.assertTrue(g.export_to_file(tmp.name, include_metadata=False))
            with open(tmp.name, "r") as f:
                data = json.load(f)
            self.assertEqual(data["graph"]["nodes"], [])
            self.assertEqual(data["graph"]["edges"], [])
        finally:
            g.close()
            os.unlink(tmp.name)

    def test_close_removes_temp_files(self):
        g = StreamingOpenGraph()
        node_path = g._node_path
        edge_path = g._edge_path
        self.assertTrue(os.path.exists(node_path))
        self.assertTrue(os.path.exists(edge_path))
        g.close()
        self.assertFalse(os.path.exists(node_path))
        self.assertFalse(os.path.exists(edge_path))


if __name__ == "__main__":
    unittest.main()
