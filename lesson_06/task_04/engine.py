#незнаю як в пайтоні отримати корінь з +- норм точністю
#тому написав примітивний бінарний пошук
def decrypt(ct, e):
    #оптимізований старт
    start = 3 * 1000000000000000000000000000000000000000000000 
    end = ct

    while start <= end:
        mid = (start + end) // 2
        if mid ** e == ct:
            return mid
        elif mid ** e < ct:
            start = mid + 1
        else:
            end = mid - 1

    return -1 