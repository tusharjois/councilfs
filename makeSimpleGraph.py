import matplotlib.pyplot as plt

NAMES=["verify", "proof"]

for name in NAMES:
    with open(name + "Execution.dat", "r") as read_f:
        plot_coordinates = read_f.readlines()
        X = []
        Y = []
        for line in plot_coordinates:
            pair = line.split(" ")
            time = float(pair[0][:-3])
            file_byte_size = int(pair[1])
            X.append(file_byte_size)
            Y.append(time)
        fig = plt.figure()
        plt.plot(X,Y)
        plt.xlabel("Size of File (bytes)")
        plt.ylabel("Time to do POR calculation (sec)")
        plt.savefig(name + ".png")

