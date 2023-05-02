# import library
import unittest


# create a class
class TestXXXXX(unittest.TestCase):
    # define a function
    def test_xxxxxxx(self):
        data = [100, 200, 300]
        result = sum(data)
        self.assertEqual(result, 600)


# driver code
if __name__ == "__main__":
    unittest.main()
