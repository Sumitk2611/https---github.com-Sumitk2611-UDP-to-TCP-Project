import matplotlib

matplotlib.use("TkAgg")  # Set an interactive backend
import matplotlib.pyplot as plt
import datetime


class Graph:
    def __init__(self, title):
        self.packets = [0]  # Time of packets sent
        self.start_time = datetime.datetime.now()
        self.title = title

        # Initialize the figure and axis
        self.fig, self.ax = plt.subplots()
        plt.ion()  # Interactive mode for real-time updates
        self.fig.canvas.manager.set_window_title(self.title)

    def update(self):
        """Update the graph with the latest packet data."""
        seconds = self.packets
        packet_count = list(range(len(self.packets)))

        self.ax.clear()  # Clear previous plot
        self.ax.plot(seconds, packet_count, marker="o", label="Packets")

        # Set labels and title
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Number of Packets")
        self.ax.set_title(self.title)
        self.ax.legend()

        # Autoscale axes
        self.ax.relim()
        self.ax.autoscale_view()

        plt.draw()  # Redraw the plot
        plt.pause(0.1)  # Pause for a moment to show the update

    def add_packet(self):
        """Add a new packet timestamp."""
        current_time = datetime.datetime.now()
        time_diff = (current_time - self.start_time).total_seconds()
        self.packets.append(time_diff)

    def reset(self):
        """Reset the packet tracking."""
        self.start_time = datetime.datetime.now()
        self.packets = [0]

    def run(self):
        """Run the graphing loop."""
        self.update()
        plt.show(block=False)

    def close(self):
        plt.close()


# Example Usage
if __name__ == "__main__":
    graph = Graph("Packet Graph")
    graph.run()

    import time

    for i in range(10):
        time.sleep(1)  # Simulate packet addition at 1-second intervals
        graph.add_packet()
        graph.update()

    plt.ioff()  # Turn off interactive mode
    plt.show()  # Keep the plot open
