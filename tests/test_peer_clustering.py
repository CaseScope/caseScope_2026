import importlib.util
import sys
import types
import unittest

import numpy as np


class _FakeSession:
    def __init__(self):
        self.added = []
        self._next_id = 1

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        for obj in self.added:
            if getattr(obj, 'id', None) is None:
                obj.id = self._next_id
                self._next_id += 1


class _FakeDb:
    def __init__(self):
        self.session = _FakeSession()


class _FakePeerGroup:
    def __init__(self, **kwargs):
        self.id = None
        self.__dict__.update(kwargs)


class _FakePeerGroupMember:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeProfile:
    def __init__(self, profile_id, entity_id):
        self.id = profile_id
        self.user_id = entity_id
        self.system_id = entity_id
        self.peer_group_id = None


class _IdentityScaler:
    def transform(self, values):
        return values


class PeerClusteringTestCase(unittest.TestCase):
    def _load_module(self):
        fake_db = _FakeDb()

        fake_models_database = types.ModuleType("models.database")
        fake_models_database.db = fake_db

        fake_models_behavioral = types.ModuleType("models.behavioral_profiles")
        fake_models_behavioral.UserBehaviorProfile = type("UserBehaviorProfile", (), {})
        fake_models_behavioral.SystemBehaviorProfile = type("SystemBehaviorProfile", (), {})
        fake_models_behavioral.PeerGroup = _FakePeerGroup
        fake_models_behavioral.PeerGroupMember = _FakePeerGroupMember

        fake_config = types.ModuleType("config")
        fake_config.Config = type("Config", (), {"ANALYSIS_PEER_GROUP_MIN_SIZE": 3})

        fake_sklearn = types.ModuleType("sklearn")
        fake_sklearn_cluster = types.ModuleType("sklearn.cluster")
        fake_sklearn_cluster.KMeans = object
        fake_sklearn_metrics = types.ModuleType("sklearn.metrics")
        fake_sklearn_metrics.silhouette_score = lambda *args, **kwargs: 0.0
        fake_sklearn_preprocessing = types.ModuleType("sklearn.preprocessing")
        fake_sklearn_preprocessing.MinMaxScaler = object

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "models.database",
                "models.behavioral_profiles",
                "config",
                "sklearn",
                "sklearn.cluster",
                "sklearn.metrics",
                "sklearn.preprocessing",
            ]
        }
        sys.modules["models.database"] = fake_models_database
        sys.modules["models.behavioral_profiles"] = fake_models_behavioral
        sys.modules["config"] = fake_config
        sys.modules["sklearn"] = fake_sklearn
        sys.modules["sklearn.cluster"] = fake_sklearn_cluster
        sys.modules["sklearn.metrics"] = fake_sklearn_metrics
        sys.modules["sklearn.preprocessing"] = fake_sklearn_preprocessing

        try:
            spec = importlib.util.spec_from_file_location(
                "peer_clustering_under_test",
                "/opt/casescope/utils/peer_clustering.py",
            )
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return module, fake_db

    def test_small_clusters_are_reassigned_instead_of_dropped(self):
        module, fake_db = self._load_module()
        builder = module.PeerGroupBuilder.__new__(module.PeerGroupBuilder)
        builder.case_id = 42
        builder.analysis_id = "analysis-42"
        builder.min_group_size = 2
        builder._calculate_peer_statistics = lambda member_profiles, group_type: {
            "median_daily_logons": float(len(member_profiles)),
        }
        builder._calculate_z_scores = lambda profile, group_stats, group_type: {"daily_logons": 0.0}

        profiles = [_FakeProfile(1, 101), _FakeProfile(2, 102), _FakeProfile(3, 103)]
        profile_ids = [profile.id for profile in profiles]
        labels = np.array([0, 0, 1])
        centers = np.array([[0.0, 0.0], [0.1, 0.1]])
        features = np.array([[0.0, 0.0], [0.0, 0.1], [0.1, 0.1]])

        groups_created = builder._create_peer_groups(
            "user",
            profiles,
            profile_ids,
            labels,
            centers,
            features,
            _IdentityScaler(),
        )

        peer_groups = [obj for obj in fake_db.session.added if isinstance(obj, _FakePeerGroup)]
        members = [obj for obj in fake_db.session.added if isinstance(obj, _FakePeerGroupMember)]

        self.assertEqual(groups_created, 1)
        self.assertEqual(len(peer_groups), 1)
        self.assertEqual(peer_groups[0].member_count, 3)
        self.assertEqual(len(members), 3)
        self.assertTrue(all(profile.peer_group_id == peer_groups[0].id for profile in profiles))


if __name__ == "__main__":
    unittest.main()
