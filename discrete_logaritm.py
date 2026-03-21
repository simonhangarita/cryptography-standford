"""
Let g be some element in Z_p^* such that h=g^x where 1<x<2^40 our goal is to find x.
In this case the idea is to use an algoritm based on the meet in the middle attack to find x in aproximately 2^20 iterations.
Instead of just trying out the 2^40 options.
So, we are going to use the following equation. Let B=2^20 and we can write the unknown x as:
x=x_0*B+x_1 and replacing in the equation we start with. We get:
h/g^x_1=(g^B)^x_0 Which we can use for the man in the middle attack
"""
#First, we define the variables that are given to us
p=13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
g=11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
h=3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333
B=2**20
#Now we build a hashmap to store the posible values for h​/g^x_1 and the value for x_1
#so that we can easily compare after with the other side of the equation
possible_values=dict()
for x_1 in range(B):
    #A collition in this case has a very low probability and in case the value is overwrite by a collition we would have 2 possible solutions
    #Which has even lower probability, so we just asume a unique solution for this problem
    possible_values[(h*pow(g, -x_1, p))%p]=x_1
#Now we can compare and in case we get a collition we have found our value for x_0 and x_1 and we can get x
#We precalculate g^B to avoid heavy recalculations in each iteration
gB=pow(g,B,p)
current_value = 1
for x_0 in range(B):
    if current_value in possible_values:
        print(f"We have found a collision and our value for x is: {x_0*B+possible_values[current_value]}")
        break
    #We multiply by the g^B in each iteration instead of doing the exponantiation which is a heavier operation than the multiplication
    current_value=(current_value * gB) % p
 