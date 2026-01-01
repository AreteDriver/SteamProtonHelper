"""ProtonDB game lookup panel."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QFrame, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import fetch_protondb_info, search_steam_games


class ProtonDBWorker(QThread):
    """Background worker for ProtonDB lookups."""

    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, app_id: str, parent=None):
        super().__init__(parent)
        self.app_id = app_id

    def run(self):
        try:
            info = fetch_protondb_info(self.app_id)
            if info:
                self.result.emit(info)
            else:
                self.error.emit("No ProtonDB data found for this game.")
        except Exception as e:
            self.error.emit(str(e))


class GameSearchWorker(QThread):
    """Background worker for Steam game search."""

    result = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, query: str, parent=None):
        super().__init__(parent)
        self.query = query

    def run(self):
        try:
            games = search_steam_games(self.query, limit=10)
            self.result.emit(games)
        except Exception as e:
            self.error.emit(str(e))


class ProtonDBPanel(QWidget):
    """Panel for looking up game compatibility on ProtonDB."""

    # Tier colors
    TIER_COLORS = {
        "platinum": "#b4c7dc",
        "gold": "#cfb53b",
        "silver": "#a8a8a8",
        "bronze": "#cd7f32",
        "borked": "#ff0000",
        "pending": "#808080",
        "native": "#00ff00",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._search_worker = None
        self._lookup_worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Search section
        search_group = QGroupBox("Search for Game")
        search_layout = QVBoxLayout(search_group)

        input_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter game name or Steam App ID...")
        self.search_input.returnPressed.connect(self._on_search)
        input_layout.addWidget(self.search_input)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._on_search)
        input_layout.addWidget(self.search_btn)

        search_layout.addLayout(input_layout)

        # Search results
        self.results_list = QListWidget()
        self.results_list.setMaximumHeight(150)
        self.results_list.itemDoubleClicked.connect(self._on_game_selected)
        self.results_list.setVisible(False)
        search_layout.addWidget(self.results_list)

        layout.addWidget(search_group)

        # Results section
        self.results_group = QGroupBox("Compatibility Info")
        results_layout = QVBoxLayout(self.results_group)

        # Game title
        self.game_title = QLabel()
        self.game_title.setStyleSheet("font-size: 18px; font-weight: bold;")
        results_layout.addWidget(self.game_title)

        # Tier badge
        self.tier_frame = QFrame()
        self.tier_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.tier_frame.setMinimumHeight(60)
        tier_layout = QVBoxLayout(self.tier_frame)

        self.tier_label = QLabel()
        self.tier_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tier_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        tier_layout.addWidget(self.tier_label)

        results_layout.addWidget(self.tier_frame)

        # Stats
        stats_layout = QHBoxLayout()

        self.score_label = QLabel()
        stats_layout.addWidget(self.score_label)

        self.reports_label = QLabel()
        stats_layout.addWidget(self.reports_label)

        self.confidence_label = QLabel()
        stats_layout.addWidget(self.confidence_label)

        stats_layout.addStretch()
        results_layout.addLayout(stats_layout)

        # Trending tier
        self.trending_label = QLabel()
        results_layout.addWidget(self.trending_label)

        # Link to ProtonDB
        link_layout = QHBoxLayout()
        self.protondb_link = QPushButton("View on ProtonDB")
        self.protondb_link.clicked.connect(self._open_protondb)
        self.protondb_link.setEnabled(False)
        link_layout.addWidget(self.protondb_link)
        link_layout.addStretch()
        results_layout.addLayout(link_layout)

        results_layout.addStretch()

        self.results_group.setVisible(False)
        layout.addWidget(self.results_group)

        # Status
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        self._current_app_id = None

    def _on_search(self):
        """Handle search button click."""
        query = self.search_input.text().strip()
        if not query:
            return

        # Check if it's a numeric App ID
        if query.isdigit():
            self._lookup_game(query)
            return

        # Otherwise search by name
        self._search_games(query)

    def _search_games(self, query: str):
        """Search for games by name."""
        self.search_btn.setEnabled(False)
        self.status_label.setText("Searching...")

        self._search_worker = GameSearchWorker(query)
        self._search_worker.result.connect(self._on_search_results)
        self._search_worker.error.connect(self._on_search_error)
        self._search_worker.start()

    @pyqtSlot(list)
    def _on_search_results(self, games: list):
        """Handle search results."""
        self.search_btn.setEnabled(True)
        self.status_label.setText("")

        self.results_list.clear()
        if games:
            self.results_list.setVisible(True)
            for game in games:
                item = QListWidgetItem(f"{game['name']} (AppID: {game['appid']})")
                item.setData(Qt.ItemDataRole.UserRole, game)
                self.results_list.addItem(item)
        else:
            self.results_list.setVisible(False)
            self.status_label.setText("No games found.")

    @pyqtSlot(str)
    def _on_search_error(self, error: str):
        """Handle search error."""
        self.search_btn.setEnabled(True)
        self.status_label.setText(f"Search error: {error}")

    def _on_game_selected(self, item: QListWidgetItem):
        """Handle game selection from search results."""
        game = item.data(Qt.ItemDataRole.UserRole)
        if game:
            self._lookup_game(str(game['appid']))
            self.results_list.setVisible(False)

    def _lookup_game(self, app_id: str):
        """Look up ProtonDB info for a game."""
        self._current_app_id = app_id
        self.search_btn.setEnabled(False)
        self.status_label.setText(f"Looking up App ID {app_id}...")

        self._lookup_worker = ProtonDBWorker(app_id)
        self._lookup_worker.result.connect(self._on_lookup_result)
        self._lookup_worker.error.connect(self._on_lookup_error)
        self._lookup_worker.start()

    @pyqtSlot(dict)
    def _on_lookup_result(self, info: dict):
        """Handle ProtonDB lookup result."""
        self.search_btn.setEnabled(True)
        self.status_label.setText("")
        self.results_group.setVisible(True)

        # Game title
        name = info.get('name', f"App ID: {self._current_app_id}")
        self.game_title.setText(name)

        # Tier
        tier = info.get('tier', 'pending').lower()
        tier_display = tier.upper()
        color = self.TIER_COLORS.get(tier, "#808080")

        self.tier_label.setText(tier_display)
        self.tier_frame.setStyleSheet(
            f"background-color: {color}; border-radius: 5px;"
        )

        # Adjust text color for readability
        if tier in ["platinum", "silver", "native"]:
            self.tier_label.setStyleSheet("font-size: 24px; font-weight: bold; color: black;")
        else:
            self.tier_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")

        # Stats
        score = info.get('score', 'N/A')
        self.score_label.setText(f"Score: {score}")

        reports = info.get('total', info.get('reports', 'N/A'))
        self.reports_label.setText(f"Reports: {reports}")

        confidence = info.get('confidence', 'N/A')
        self.confidence_label.setText(f"Confidence: {confidence}")

        # Trending
        trending = info.get('trendingTier', '')
        if trending and trending != tier:
            self.trending_label.setText(f"Trending: {trending.upper()}")
            self.trending_label.setVisible(True)
        else:
            self.trending_label.setVisible(False)

        self.protondb_link.setEnabled(True)

    @pyqtSlot(str)
    def _on_lookup_error(self, error: str):
        """Handle lookup error."""
        self.search_btn.setEnabled(True)
        self.status_label.setText(error)
        self.results_group.setVisible(False)

    def _open_protondb(self):
        """Open ProtonDB page in browser."""
        if self._current_app_id:
            url = f"https://www.protondb.com/app/{self._current_app_id}"
            QDesktopServices.openUrl(QUrl(url))
