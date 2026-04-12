import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase6ChatAgentDispatchContractTestCase(unittest.TestCase):
    def test_chat_agent_uses_shared_tool_dispatcher(self):
        with open(
            os.path.join(REPO_ROOT, 'utils', 'chat_agent.py'),
            'r',
            encoding='utf-8',
        ) as handle:
            source = handle.read()

        self.assertIn('from utils.chat import Provenance, ToolDispatcher, ToolTier', source)
        self.assertIn('_TOOL_DISPATCHER = ToolDispatcher(execute_tool)', source)
        self.assertIn('tool_result = _TOOL_DISPATCHER.execute(', source)
        self.assertIn('result = tool_result.to_payload()', source)


if __name__ == '__main__':
    unittest.main()
