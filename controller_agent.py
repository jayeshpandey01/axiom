"""Entrypoint for the dedicated Linux Controller Agent."""
from controller.agent import ControllerAgent

if __name__ == "__main__":
    agent = ControllerAgent()
    agent.run_loop()
