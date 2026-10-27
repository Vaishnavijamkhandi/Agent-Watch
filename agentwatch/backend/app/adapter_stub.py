"""Extension stub only: AgentDojo-style benchmark adapters are not bundled or required."""
class AgentDojoAdapter:
    """Placeholder interface for a future external benchmark adapter; no benchmark is run here."""
    name = 'AgentDojo-style adapter extension stub'
    def available(self) -> bool:
        return False
    def run(self, *args, **kwargs):
        raise NotImplementedError('External benchmark adapter is an extension, not included in this prototype.')
