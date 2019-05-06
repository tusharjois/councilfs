import matplotlib.pyplot as plt

NAMES=["verify", "proof"]

for name in NAMES:
    with open(name + "Execution.dat", "r") as read_f:
        plot_coordinates = read_f.readlines()
        X = []
        Y = []
        for line in plot_coordinates:
            pair = line.split(" ")
            time = float(pair[0])
            file_byte_size = long(pair[1])
            X.append(file_byte_size)
            Y.append(time)
        fig = plt.figure()
        plt.plot(X,Y)
        if name == "verify":
            plt.suptitle("Time vs Number of Segments for POR Verification")
        else:
            plt.suptitle("Time vs Number of Segments for Producing POR")
        plt.ticklabel_format(style='plain', axis='x')
        plt.xlabel("Security parameter k")
        plt.ylabel("Time to do POR calculation (sec)")
        plt.savefig(name + ".png")

