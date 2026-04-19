#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : opengraph_context.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025


import ntpath
from typing import List, Optional, Tuple, Union

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph

import sharehound.kinds as kinds
from sharehound.core.Logger import Logger, TaskLogger


class OpenGraphContext:
    """
    Context manager for building OpenGraph structures representing SMB share hierarchies.

    This class maintains the current context while traversing SMB shares, tracking the host,
    current share, directory path, and current element being processed. It provides methods
    to build the graph structure incrementally as the share is explored.

    Graph Structure:
        (Host) --[HasNetworkShare]--> (NetworkShareSMB|NetworkShareDFS) --[Contains]--> (Directory|File)*

    Attributes:
        graph (OpenGraph): The OpenGraph instance to populate
        host (Optional[Node]): The host node representing the SMB server
        share (Optional[Tuple[Node, dict]]): Current share node and its rights
        path (List[Tuple[Node, dict]]): List of directory nodes in current path with their rights
        element (Optional[Tuple[Node, dict]]): Current file/directory element and its rights

    Methods:
        set_host: Set the host node
        get_host: Get the host node
        set_share: Set the current share node and rights
        get_share: Get the current share node
        push_directory: Add a directory to the current path
        pop_directory: Remove the last directory from the current path
        set_element: Set the current element (file or directory)
        get_element: Get the current element
        add_path_to_graph: Add the current path structure to the graph
        add_rights_to_graph: Add access rights for a node to the graph

    """

    host: Optional[Node]
    share: Optional[Tuple[Node, dict]]
    path: List[Tuple[Node, dict]]
    element: Optional[Tuple[Node, dict]]
    logger: Optional[Union[Logger, TaskLogger]]
    total_edges_created: int

    def __init__(
        self, graph: OpenGraph, logger: Optional[Union[Logger, TaskLogger]] = None
    ):
        self.graph = graph
        self.host = (None, {})
        self.share = (None, {})
        self.path = []
        self.element = (None, {})
        self.logger = logger
        self.total_edges_created = 0

    def add_path_to_graph(self) -> None:
        """
        Add the path to the graph

        Args:
            None

        Returns:
            None
        """
        # Set base host and share nodes
        if self.host is None:
            if self.logger:
                self.logger.debug("[add_path_to_graph] Host is None, skipping")
            return None
        self.graph.add_node_without_validation(self.host)

        # Add edge [HostsNetworkShare] from BloodHound Computer to NetworkShareHost
        # This links the ShareHound graph to existing BloodHound Computer nodes
        # by matching the Computer's name property (uppercase) to the NetworkShareHost's id
        self.graph.add_edge_without_validation(
            Edge(
                start_node=self.host.id.upper(),
                end_node=self.host.id,
                kind=kinds.edge_kind_hosts_network_share,
                start_match_by="name",
                end_match_by="id",
            )
        )
        self.total_edges_created += 1
        if self.logger:
            self.logger.debug(
                f"[add_path_to_graph] Created edge HostsNetworkShare: Computer(name={self.host.id.upper()}) -> NetworkShareHost(id={self.host.id})"
            )

        share_node, share_rights = self.share
        if share_node is None:
            if self.logger:
                self.logger.debug("[add_path_to_graph] Share node is None, skipping")
            return None
        self.graph.add_node_without_validation(share_node)

        if self.logger:
            rights_count = (
                sum(len(edges) for edges in share_rights.values())
                if share_rights
                else 0
            )
            self.logger.debug(
                f"[add_path_to_graph] Adding share '{share_node.id}' with {len(share_rights)} SID(s) and {rights_count} rights edge(s)"
            )

        self.add_rights_to_graph(share_node.id, share_rights, "share")

        # Add edge [HasNetworkShare] from host to share
        self.graph.add_edge_without_validation(
            Edge(
                start_node=self.host.id,
                end_node=share_node.id,
                kind=kinds.edge_kind_has_network_share,
            )
        )
        self.total_edges_created += 1
        if self.logger:
            self.logger.debug(
                f"[add_path_to_graph] Created edge HasNetworkShare: {self.host.id} -> {share_node.id}"
            )

        # At this point we have created
        # (Host) --[HasNetworkShare]--> ((NetworkShareSMB|NetworkShareDFS))

        # Add edges [Contains] from parent to directory
        parent_id = share_node.id
        for directory in self.path:
            directory_node, directory_rights = directory
            self.graph.add_node_without_validation(directory_node)
            self.add_rights_to_graph(directory_node.id, directory_rights, "directory")
            self.graph.add_edge_without_validation(
                Edge(
                    start_node=parent_id,
                    end_node=directory_node.id,
                    kind=kinds.edge_kind_contains,
                )
            )
            self.total_edges_created += 1
            if self.logger:
                self.logger.debug(
                    f"[add_path_to_graph] Created edge Contains: {parent_id} -> {directory_node.id}"
                )
            parent_id = directory_node.id

        # At this point we have created
        # (Host) --[Expose]--> ((NetworkShareSMB|NetworkShareDFS)) --[Contains]--> ((File)|(Directory))*

        # Add edge [Contains] from parent to element

        element_node, element_rights = self.element
        if element_node is None:
            return None
        self.graph.add_node_without_validation(element_node)
        self.add_rights_to_graph(element_node.id, element_rights, "file")

        self.graph.add_edge_without_validation(
            Edge(
                start_node=parent_id,
                end_node=element_node.id,
                kind=kinds.edge_kind_contains,
            )
        )
        self.total_edges_created += 1
        if self.logger:
            self.logger.debug(
                f"[add_path_to_graph] Created edge Contains: {parent_id} -> {element_node.id}"
            )

        # At this point we have created
        # (Host) --[Expose]--> ((NetworkShareSMB|NetworkShareDFS)) --[Contains]--> ((File)|(Directory))* --[Contains]--> ((File)|(Directory))

    def add_rights_to_graph(
        self, element_id: str, rights: dict, element_type: str = "element"
    ) -> None:
        """
        Add rights to the graph

        Args:
            element_id: The id of the element
            rights: The rights to add
            element_type: Type of element for logging (share, directory, file)

        Returns:
            None
        """

        if rights is None:
            if self.logger:
                self.logger.warning(
                    f"[add_rights_to_graph] Rights is None for {element_type}: {element_id}"
                )
            return

        if len(rights) == 0:
            if self.logger:
                self.logger.debug(
                    f"[add_rights_to_graph] No rights to add for {element_type}: {element_id}"
                )
            return

        edges_created_for_element = 0
        for sid, rights_edges in rights.items():
            # Principal nodes (Users/Groups) already exist from AD collection
            # Just create edges from SIDs to the share/file elements
            for right_edge in rights_edges:
                self.graph.add_edge_without_validation(
                    Edge(
                        start_node=sid,
                        end_node=element_id,
                        kind=right_edge,
                    )
                )
                self.total_edges_created += 1
                edges_created_for_element += 1
                if self.logger:
                    self.logger.debug(
                        f"[add_rights_to_graph] Created edge: {sid} --[{right_edge}]--> {element_id}"
                    )

        if self.logger:
            self.logger.debug(
                f"[add_rights_to_graph] Created {edges_created_for_element} rights edge(s) for {element_type}: {element_id}"
            )

    def push_path(self, node: Node, rights: dict):
        """
        Add a node to the path stack

        Args:
            node: The node to add
            rights: The rights to add

        Returns:
            None
        """
        self.path.append((node, rights))

    def pop_path(self) -> Optional[Node]:
        """
        Remove and return the last node from the path stack

        Args:
            None

        Returns:
            The last node from the path stack
        """
        if self.path:
            return self.path.pop()[0]
        return None

    # Getter and setter

    def set_element(self, element: Node) -> None:
        """
        Set the element node

        Args:
            element: The element node to set

        Returns:
            None
        """
        self.element = (element, self.element[1])

    def set_element_rights(self, rights: dict) -> None:
        """
        Set the element rights

        Args:
            rights: The rights to set

        Returns:
            None
        """
        if rights is None:
            rights = {}
        self.element = (self.element[0], rights)

    def get_element_rights(self):
        """
        Get the element rights
        """
        return self.element[1]

    def get_element(self):
        """
        Get the element node
        """
        return self.element[0]

    def set_directory_rights(self, rights: dict) -> None:
        """
        Set rights for the last directory in the path

        Args:
            rights: The rights to set

        Returns:
            None
        """
        if self.path and rights is not None:
            node, _ = self.path[-1]
            self.path[-1] = (node, rights)

    def clear_element(self):
        """
        Clear the element

        Args:
            None

        Returns:
            None
        """
        self.element = (None, {})

    def get_path(self):
        """
        Get the path

        Args:
            None

        Returns:
            The path
        """
        return self.path

    def get_string_path_from_root(self) -> str:
        """
        Get the string path from the root

        Args:
            None

        Returns:
            The string path from the root
        """
        return ntpath.sep.join(
            [node.properties.get_property("name") for (node, _) in self.path]
        )

    def clear_path(self):
        """
        Clear the path

        Args:
            None

        Returns:
            None
        """
        self.path = []

    def set_host(self, host: Node):
        """
        Set the host

        Args:
            host: The host node to set

        Returns:
            None
        """
        self.host = host

    def get_host(self):
        """
        Get the host

        Args:
            None

        Returns:
            The host node
        """
        return self.host

    def clear_host(self):
        """
        Clear the host

        Args:
            None

        Returns:
            None
        """
        self.host = None

    def set_share(self, share: Node) -> None:
        """
        Set the share

        Args:
            share: The share node to set

        Returns:
            None
        """
        self.share = (share, self.share[1])

    def get_share(self):
        """
        Get the share

        Args:
            None

        Returns:
            The share node
        """
        return self.share[0]

    def set_share_rights(self, rights: dict) -> None:
        """
        Set the share rights

        Args:
            rights: The rights to set

        Returns:
            None
        """
        self.share = (self.share[0], rights)

    def get_share_rights(self) -> dict:
        """
        Get the share rights

        Args:
            None

        Returns:
            The share rights
        """
        return self.share[1]

    def clear_share(self):
        """
        Clear the share

        Args:
            None

        Returns:
            None
        """
        self.share = (None, {})

    def get_total_edges_created(self) -> int:
        """
        Get the total number of edges created by this context.

        Args:
            None

        Returns:
            int: Total edges created
        """
        return self.total_edges_created

    def log_summary(self) -> None:
        """
        Log a summary of edges created by this context.

        Args:
            None

        Returns:
            None
        """
        if self.logger:
            self.logger.debug(
                f"[OpenGraphContext] Total edges created in this context: {self.total_edges_created}"
            )
